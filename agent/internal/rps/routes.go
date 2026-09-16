package rps

import (
	"sort"
	"sync"
)

const MaxRoutes = 512

type Route struct {
	Server   string `json:"server"`
	Location string `json:"location"`
	ID       string `json:"id,omitempty"`
}

type RouteRates struct {
	Route
	RPS   float64     `json:"rps"`
	Codes StatusRates `json:"codes"`
}

type Routes struct {
	mu   sync.Mutex
	rows map[Route]*Counter
	max  int
	now  func() int64

	dropped uint64
}

func NewRoutes() *Routes {
	return &Routes{rows: make(map[Route]*Counter), max: MaxRoutes}
}

func (r *Routes) Add(server, location, id string, status int, verdict string) {
	if server == "" && location == "" {
		return
	}

	key := Route{Server: server, Location: location, ID: id}

	r.mu.Lock()
	defer r.mu.Unlock()

	c, ok := r.rows[key]
	if !ok {
		if len(r.rows) >= r.max && !r.evictSilent() {
			r.dropped++
			return
		}

		c = &Counter{now: r.now}
		r.rows[key] = c
	}

	c.Add(status, verdict)
}

func (r *Routes) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.dropped
}

func (r *Routes) Snapshot() []RouteRates {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]RouteRates, 0, len(r.rows))

	for key, c := range r.rows {
		rate := c.Rate()
		if rate == 0 {
			delete(r.rows, key)
			continue
		}

		out = append(out, RouteRates{Route: key, RPS: rate, Codes: c.Status()})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}

		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}

		return out[i].ID < out[j].ID
	})

	return out
}

func (r *Routes) evictSilent() bool {
	freed := false

	for key, c := range r.rows {
		if c.Rate() == 0 {
			delete(r.rows, key)
			freed = true
		}
	}

	return freed
}
