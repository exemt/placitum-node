/*
 * Наблюдение за настройками агента.
 *
 * Отдельный watcher, а не ветка в Watch: тот включается только у ноды, которая
 * ведёт nginx (NginxManage) и знает Redis, — а архив ведут как раз остальные.
 * Связать их значило бы, что сайдкар, который только и делает, что возит
 * объекты в S3, единственный и не получает настройку архива.
 *
 * Ошибка применения не роняет процесс: настройка приходит извне, и «контроллер
 * прислал адрес хранилища, реквизитов к которому у ноды нет» — это состояние
 * конфигурации. Нода остаётся на прежней настройке и говорит об этом в пульсе,
 * а не падает в рестарт-цикл, унося с собой живой трафик.
 */

package desired

import (
	"context"
	"log/slog"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// AgentApplied — что нода реально применила. Пустая ревизия означает, что
// контроллер настройку ещё не присылал и работает то, что дал файл ноды.
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

// WatchAgentConf подписывается на policy/agent-conf и зовёт apply на каждую
// новую ревизию. Первым событием прилетает то, что уже лежит в KV, — нода,
// поднявшаяся после раскатки, получает настройку сразу, а не ждёт следующей.
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
