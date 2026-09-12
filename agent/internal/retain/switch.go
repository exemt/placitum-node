/*
 * Смена настройки архива без рестарта.
 *
 * Пул архивации собирается один раз: очередь, воркеры, корзины и клиент S3
 * заданы конфигурацией на момент New. Перенастроить его на месте нельзя, не
 * заведя блокировку в горячем пути, — и не нужно: пул дёшев, а замена целиком
 * честнее половинчатой правки, при которой воркеры уже пишут в новый бакет, а
 * корзины ещё считают по старому размеру.
 *
 * Поэтому Switch держит указатель на текущий пул и подменяет его атомарно.
 * Старый пул закрывается в фоне: Close даёт воркерам дописать очередь, и
 * записи, принятые до раскатки, доезжают по старому адресу вместо того чтобы
 * пропасть вместе с настройкой. Отсюда же и общий счётчик темпа: канал
 * `archive` в пульсе не должен обнуляться на каждой раскатке.
 */

package retain

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/exemt/placitum-node/agent/internal/audit"
	"github.com/exemt/placitum-node/agent/internal/flow"
)

type Switch struct {
	cur     atomic.Pointer[Pool]
	io      *flow.Counter
	publish Publisher
	log     *slog.Logger

	// swap сериализует замену: две раскатки подряд не должны потерять пул.
	swap sync.Mutex
	// gone ждёт закрытия отставленных пулов, чтобы Close не вернулся раньше,
	// чем они дописали свои очереди.
	gone sync.WaitGroup

	closed atomic.Bool
}

func NewSwitch(cfg Config, publish Publisher, log *slog.Logger) *Switch {
	io := flow.New()
	s := &Switch{io: io, publish: publish, log: log}
	s.cur.Store(NewShared(cfg, publish, log, io))
	return s
}

// Handle — тот же единственный вход, что у пула.
func (s *Switch) Handle(d audit.Decision) {
	s.cur.Load().Handle(d)
}

func (s *Switch) IO() flow.Flow {
	return s.io.Snapshot()
}

// Config — настройка работающего пула. Нужна оверлею: документ контроллера
// кладётся поверх того, что дала нода, а не поверх предыдущего документа.
func (s *Switch) Config() Config {
	return s.cur.Load().cfg
}

func (s *Switch) Enabled() bool {
	return s.cur.Load().cfg.enabled()
}

/*
 * Apply ставит новую настройку. Непринятая настройка — не авария: пул
 * остаётся прежним, ошибка уходит наверх и попадает в пульс. Чаще всего это
 * «эндпоинт есть, реквизитов нет»: контроллер про секреты ноды не знает и
 * знать не должен.
 */
func (s *Switch) Apply(cfg Config) error {
	if err := cfg.Finish(); err != nil {
		return err
	}

	s.swap.Lock()
	defer s.swap.Unlock()

	if s.closed.Load() {
		return nil
	}

	old := s.cur.Load()
	s.cur.Store(NewShared(cfg, s.publish, s.log, s.io))

	s.gone.Add(1)
	go func() {
		defer s.gone.Done()
		old.Close()
	}()

	return nil
}

func (s *Switch) Close() {
	s.swap.Lock()
	s.closed.Store(true)
	cur := s.cur.Load()
	s.swap.Unlock()

	cur.Close()
	s.gone.Wait()
}
