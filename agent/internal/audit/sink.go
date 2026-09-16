package audit

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-shared/flow"
)

const KindBatch = "batch"

const (
	maxItems = 256
	maxSize  = 512 << 10

	flushEvery = 50 * time.Millisecond

	maxPending = 50000
)

type item struct {
	node string
	body []byte
}

type envelope struct {
	V     int               `json:"v"`
	Kind  string            `json:"kind"`
	Node  string            `json:"node,omitempty"`
	Items []json.RawMessage `json:"items"`
}

type Sink struct {
	nc  *nats.Conn
	io  *flow.Counter
	log *slog.Logger

	mu      sync.Mutex
	pending []item
	size    int
	dropped uint64

	wake chan struct{}
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

func NewSink(nc *nats.Conn, io *flow.Counter, log *slog.Logger) *Sink {
	s := &Sink{
		nc:   nc,
		io:   io,
		log:  log,
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}

	go s.loop()

	return s
}

func (s *Sink) Add(d Decision) error {
	if s == nil || s.nc == nil || d.Ray == "" || d.Node == "" || d.Verdict == "" {
		return nil
	}

	inject := ""
	if !hasNode(d.Raw) {
		inject = d.Node
	}

	body, err := Envelope(d.Raw, inject)
	if err != nil {
		return err
	}

	s.mu.Lock()

	s.pending = append(s.pending, item{node: d.Node, body: body})
	s.size += len(body) + 2

	if len(s.pending) > maxPending {
		cut := len(s.pending) - maxPending
		s.dropped += uint64(cut)
		s.pending = append(s.pending[:0], s.pending[cut:]...)
		s.size = sizeOf(s.pending)
	}

	full := len(s.pending) >= maxItems || s.size >= maxSize
	s.mu.Unlock()

	if full {
		s.kick()
	}

	return nil
}

func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}

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
		if n > maxItems {
			n = maxItems
		}

		take := make([]item, n)
		copy(take, s.pending[:n])

		s.pending = append(s.pending[:0], s.pending[n:]...)
		s.size = sizeOf(s.pending)
		s.mu.Unlock()

		s.publish(take)
	}
}

func (s *Sink) publish(items []item) {
	if len(items) == 1 {
		s.send(items[0].node, items[:1])

		return
	}

	order, byNode := groupByNode(items)

	for _, node := range order {
		s.send(node, byNode[node])
	}
}

func groupByNode(items []item) ([]string, map[string][]item) {
	byNode := make(map[string][]item, 1)
	order := make([]string, 0, 1)

	for _, it := range items {
		if _, ok := byNode[it.node]; !ok {
			order = append(order, it.node)
		}

		byNode[it.node] = append(byNode[it.node], it)
	}

	return order, byNode
}

func (s *Sink) send(node string, items []item) {
	start := time.Now()

	body, err := pack(node, items)
	if err == nil {
		err = s.nc.Publish(Subject(node), body)
	}

	if s.io != nil {
		s.io.AddN(len(items), 0, uint64(len(body)), err != nil, time.Since(start))
	}

	if err != nil && s.log != nil {
		s.log.Warn("audit publish failed",
			"node", node, "records", len(items), "error", err.Error())
	}
}

func pack(node string, items []item) ([]byte, error) {
	raw := make([]json.RawMessage, 0, len(items))

	for _, it := range items {
		raw = append(raw, json.RawMessage(it.body))
	}

	return json.Marshal(envelope{
		V:     Version,
		Kind:  KindBatch,
		Node:  node,
		Items: raw,
	})
}

func sizeOf(items []item) int {
	n := 0

	for _, it := range items {
		n += len(it.body) + 2
	}

	return n
}

func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}
