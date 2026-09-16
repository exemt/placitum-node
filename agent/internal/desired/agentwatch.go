package desired

import (
	"context"
	"log/slog"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type AgentApplied struct {
	mu     sync.RWMutex
	rev    int
	hash   string
	status string
}

func (a *AgentApplied) Snapshot() (rev int, hash string, status string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.rev, a.hash, a.status
}

func (a *AgentApplied) set(rev int, hash, status string) {
	a.mu.Lock()
	a.rev = rev
	a.hash = hash
	a.status = status
	a.mu.Unlock()
}

func WatchAgentConf(
	ctx context.Context,
	nc *nats.Conn,
	apply func(*AgentConf) error,
	log *slog.Logger,
) (*AgentApplied, error) {
	applied := &AgentApplied{}

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

	watcher, err := kv.Watch(ctx, AgentConfKey)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

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

				conf, err := ParseAgentConf(entry.Value())
				if err != nil {
					log.Warn("agent conf rejected", "error", err.Error())
					continue
				}

				rev, hash, _ := applied.Snapshot()
				if rev == conf.Rev && hash == conf.SHA256 {
					continue
				}

				if err := apply(conf); err != nil {
					log.Warn("agent conf apply failed",
						"rev", conf.Rev,
						"sha256", conf.SHA256,
						"error", err.Error(),
					)
					applied.set(conf.Rev, conf.SHA256, ApplyFailed)
					continue
				}

				applied.set(conf.Rev, conf.SHA256, ApplyOK)
				log.Info("agent conf applied", "rev", conf.Rev, "sha256", conf.SHA256)
			}
		}
	}()

	return applied, nil
}
