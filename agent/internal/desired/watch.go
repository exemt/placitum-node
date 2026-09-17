package desired

import (
	"context"
	"crypto/rsa"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
)

const Bucket = "WAF_DESIRED"

// A generation that did not apply is tried again with a growing pause: blobs the controller has not
// written yet, an upstream name that does not resolve yet. A newer generation replaces it at once.
var retryPace = backoff{first: 2 * time.Second, max: time.Minute}

type backoff struct {
	first time.Duration
	max   time.Duration
}

type Config struct {
	ConfDir  string
	StoreDir string
	NginxBin string
}

// failure is a generation that stopped at stage: fetch or apply.
type failure struct {
	stage  string
	status string
	err    error
}

func (f *failure) Error() string {
	return f.err.Error()
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

	handle := func(p *NginxPack) error {
		hash, rev, apply, conf := applied.Snapshot()
		if apply == ApplyOK && hash == p.SHA256 && rev == p.Rev {
			return nil
		}

		blobs, err := FetchBlobs(ctx, rdb, p)
		if err != nil {
			applied.set(hash, rev, ApplyFailed, conf)
			return &failure{stage: "fetch", status: ApplyFailed, err: err}
		}

		fingerprint, err := Apply(key, p, blobs, cfg.ConfDir, cfg.StoreDir, cfg.NginxBin)
		if err != nil {
			status := ApplyFailed
			if containsDecryptError(err.Error()) {
				status = Undecryptable
			}
			applied.set(hash, rev, status, conf)
			return &failure{stage: "apply", status: status, err: err}
		}

		applied.set(p.SHA256, p.Rev, ApplyOK, fingerprint)
		log.Info("desired applied",
			"rev", p.Rev,
			"hash", p.SHA256,
			"conf", fingerprint,
			"store", len(p.Store),
			"pages", len(p.Pages),
		)
		return nil
	}

	packs := make(chan *NginxPack)

	go func() {
		defer watcher.Stop()
		defer close(packs)

		for {
			select {
			case <-ctx.Done():
				return
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

				select {
				case packs <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go follow(ctx, packs, handle, retryPace, log)

	return applied, nil
}

// follow applies every generation from packs. One that fails is tried again after a pause that
// doubles up to pace.max, until it applies or the next generation arrives.
func follow(
	ctx context.Context,
	packs <-chan *NginxPack,
	try func(*NginxPack) error,
	pace backoff,
	log *slog.Logger,
) {
	var (
		pending *NginxPack
		delay   time.Duration
		retry   <-chan time.Time
	)

	run := func(p *NginxPack) {
		err := try(p)
		if err == nil {
			pending, retry = nil, nil
			return
		}

		stage, status := "apply", ApplyFailed
		var f *failure
		if errors.As(err, &f) {
			stage, status = f.stage, f.status
		}

		log.Warn("desired "+stage+" failed",
			"rev", p.Rev,
			"hash", p.SHA256,
			"status", status,
			"retry_in", delay.String(),
			"error", err.Error(),
		)

		pending, retry = p, time.After(delay)
		delay = min(2*delay, pace.max)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-packs:
			if !ok {
				return
			}
			delay = pace.first
			run(p)
		case <-retry:
			run(pending)
		}
	}
}

func containsDecryptError(msg string) bool {
	return len(msg) > 7 && (msg[:8] == "decrypt:" || (len(msg) > 20 && msg[7:15] == "store" && msg[16:20] == "decr"))
}
