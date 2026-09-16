package nginxlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-node/agent/internal/handoff"
	"github.com/exemt/placitum-shared/flow"
)

const (
	Stream  = "WAF_LOG"
	Kind    = "log"
	Version = 1

	DefaultPath = "/var/run/waf/log.sock"

	MaxBytes = 16 << 10

	readBuffer = 4 << 20

	maxLines = 500
	maxSize  = 256 << 10

	flushEvery = 200 * time.Millisecond

	maxPending = 20000

	MaxAge      = 24 * time.Hour
	StreamBytes = 128 << 20
)

func Subject(writer string) string {
	if writer == "" {
		writer = "unknown"
	}

	return "waf.log." + writer
}

type batch struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Writer string `json:"writer"`
	Lines  []Line `json:"lines"`
}

type Sink struct {
	nc     *nats.Conn
	writer string
	io     *flow.Counter
	log    *slog.Logger

	mu      sync.Mutex
	pending []Line
	size    int
	dropped uint64

	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

func NewSink(nc *nats.Conn, writer string, io *flow.Counter, log *slog.Logger) *Sink {
	s := &Sink{
		nc:     nc,
		writer: writer,
		io:     io,
		log:    log,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		stop:   make(chan struct{}),
	}

	go s.loop()

	return s
}

func (s *Sink) Add(line Line) {
	s.mu.Lock()

	s.pending = append(s.pending, line)
	s.size += len(line.Text) + 64

	if len(s.pending) > maxPending {
		cut := len(s.pending) - maxPending
		s.dropped += uint64(cut)
		s.pending = append(s.pending[:0], s.pending[cut:]...)
	}

	full := len(s.pending) >= maxLines || s.size >= maxSize
	s.mu.Unlock()

	if full {
		s.kick()
	}
}

func (s *Sink) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dropped
}

func (s *Sink) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Sink) loop() {
	defer close(s.done)

	tick := time.NewTicker(flushEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.stop:
			s.flush()
			return
		case <-s.wake:
			s.flush()
		case <-tick.C:
			s.flush()
		}
	}
}

func (s *Sink) flush() {
	for {
		s.mu.Lock()
		if len(s.pending) == 0 {
			s.mu.Unlock()
			return
		}

		n := len(s.pending)
		if n > maxLines {
			n = maxLines
		}

		lines := make([]Line, n)
		copy(lines, s.pending[:n])

		s.pending = append(s.pending[:0], s.pending[n:]...)
		s.size = 0
		for _, l := range s.pending {
			s.size += len(l.Text) + 64
		}
		s.mu.Unlock()

		s.publish(lines)
	}
}

func (s *Sink) publish(lines []Line) {
	start := time.Now()

	body, err := json.Marshal(batch{
		V:      Version,
		Kind:   Kind,
		Writer: s.writer,
		Lines:  lines,
	})
	if err == nil {
		err = s.nc.Publish(Subject(s.writer), body)
	}

	if s.io != nil {
		s.io.AddN(len(lines), 0, uint64(len(body)), err != nil, time.Since(start))
	}

	if err != nil && s.log != nil {
		s.log.Warn("nginx log publish failed", "error", err.Error(), "lines", len(lines))
	}
}

func (s *Sink) Close() {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

func Serve(nc *nats.Conn, path, writer string, io *flow.Counter,
	log *slog.Logger) (*Sink, func() error, error) {

	if nc == nil {
		return nil, nil, fmt.Errorf("nginxlog: nats connection is nil")
	}

	if path == "" {
		path = DefaultPath
	}

	sink := NewSink(nc, writer, io, log)

	stop, err := handoff.ServeOpts(path,
		handoff.Opts{Max: MaxBytes, ReadBuffer: readBuffer},
		func(raw []byte) {
			line, ok := Parse(raw, time.Now().UTC())
			if !ok {
				return
			}

			sink.Add(line)
		})
	if err != nil {
		sink.Close()

		return nil, nil, err
	}

	return sink, func() error {
		err := stop()
		sink.Close()

		return err
	}, nil
}

func Ensure(nc *nats.Conn) error {
	if nc == nil {
		return fmt.Errorf("nginxlog: nats connection is nil")
	}

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:      Stream,
		Subjects:  []string{"waf.log.>"},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		MaxAge:    MaxAge,
		MaxBytes:  StreamBytes,
		Discard:   nats.DiscardOld,
	})
	if err == nil || errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}

	return err
}
