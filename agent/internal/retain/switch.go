package retain

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/exemt/placitum-node/agent/internal/audit"
	"github.com/exemt/placitum-shared/flow"
)

type Switch struct {
	cur     atomic.Pointer[Pool]
	io      *flow.Counter
	publish Publisher
	log     *slog.Logger

	swap sync.Mutex
	gone sync.WaitGroup

	closed atomic.Bool
}

func NewSwitch(cfg Config, publish Publisher, log *slog.Logger) *Switch {
	io := flow.New()
	s := &Switch{io: io, publish: publish, log: log}
	s.cur.Store(NewShared(cfg, publish, log, io))
	return s
}

func (s *Switch) Handle(d audit.Decision) {
	s.cur.Load().Handle(d)
}

func (s *Switch) IO() flow.Flow {
	return s.io.Snapshot()
}

func (s *Switch) Config() Config {
	return s.cur.Load().cfg
}

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
