package desired

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
)

const Bucket = "WAF_DESIRED"

const fetchRetry = 30 * time.Second

type Config struct {
	ConfDir  string
	StoreDir string
	NginxBin string
}

func Watch(
	ctx context.Context,
	nc *nats.Conn,
	rdb *redis.Client,
	key *rsa.PrivateKey,
	cfg Config,
	log *slog.Logger,
) (*Applied, error) {
	applied := NewApplied(cfg.ConfDir)

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  Bucket,
		History: 5,
	})
	if err != nil {
		return nil, err
	}

	watcher, err := kv.Watch(ctx, PackKey)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

		var (
			pending *NginxPack
			retry   <-chan time.Time
		)

		handle := func(p *NginxPack) bool {
			hash, rev, apply, conf := applied.Snapshot()
			if apply == ApplyOK && hash == p.SHA256 && rev == p.Rev {
				return false
			}

			blobs, err := FetchBlobs(ctx, rdb, p)
			if err != nil {
				log.Warn("desired fetch failed",
					"rev", p.Rev,
					"hash", p.SHA256,
					"retry_in", fetchRetry.String(),
					"error", err.Error(),
				)
				applied.set(hash, rev, ApplyFailed, conf)
				return true
			}

			fingerprint, err := Apply(key, p, blobs, cfg.ConfDir, cfg.StoreDir, cfg.NginxBin)
			if err != nil {
				errMsg := err.Error()
				status := ApplyFailed
				if containsDecryptError(errMsg) {
					status = Undecryptable
				}
				log.Warn("desired apply failed",
					"rev", p.Rev,
					"hash", p.SHA256,
					"status", status,
					"error", errMsg,
				)
				applied.set(hash, rev, status, conf)
				return false
			}

			applied.set(p.SHA256, p.Rev, ApplyOK, fingerprint)
			log.Info("desired applied",
				"rev", p.Rev,
				"hash", p.SHA256,
				"conf", fingerprint,
				"store", len(p.Store),
				"pages", len(p.Pages),
			)
			return false
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-retry:
				retry = nil
				if pending == nil {
					continue
				}
				if handle(pending) {
					retry = time.After(fetchRetry)
				} else {
					pending = nil
				}
			case entry, ok := <-watcher.Updates():
				if !ok {
					return
				}
				if entry == nil {
					continue
				}

				switch entry.Operation() {
				case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
					continue
				}

				p, err := ParsePack(entry.Value())
				if err != nil {
					log.Warn("desired rejected", "error", err.Error())
					continue
				}

				pending, retry = nil, nil
				if handle(p) {
					pending = p
					retry = time.After(fetchRetry)
				}
			}
		}
	}()

	return applied, nil
}

func containsDecryptError(msg string) bool {
	return len(msg) > 7 && (msg[:8] == "decrypt:" || (len(msg) > 20 && msg[7:15] == "store" && msg[16:20] == "decr"))
}
