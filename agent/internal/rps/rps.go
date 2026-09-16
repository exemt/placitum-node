package rps

import (
	"sync"
	"time"
)

const Window = 10

type StatusRates struct {
	XX2 float64 `json:"2xx"`
	XX3 float64 `json:"3xx"`
	XX4 float64 `json:"4xx"`
	XX5 float64 `json:"5xx"`
}

type Counter struct {
	mu    sync.Mutex
	total [Window]uint64
	class [4][Window]uint64
	epoch int64
	now   func() int64
}

func New() *Counter {
	return &Counter{}
}

func Class(status int, verdict string) int {
	if status >= 200 && status < 600 {
		return status / 100
	}
	switch verdict {
	case "allow":
		return 2
	case "redirect":
		return 3
	case "deny":
		return 4
	default:
		return 0
	}
}

func (c *Counter) Add(status int, verdict string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.unix()
	c.advance(now)
	slot := now % Window
	c.total[slot]++
	if class := Class(status, verdict); class >= 2 && class <= 5 {
		c.class[class-2][slot]++
	}
}

func (c *Counter) Rate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.unix()
	c.advance(now)
	return rate(c.total)
}

func (c *Counter) Status() StatusRates {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.unix()
	c.advance(now)
	return StatusRates{
		XX2: rate(c.class[0]),
		XX3: rate(c.class[1]),
		XX4: rate(c.class[2]),
		XX5: rate(c.class[3]),
	}
}

func rate(buckets [Window]uint64) float64 {
	var sum uint64
	for _, n := range buckets {
		sum += n
	}
	return float64(sum) / float64(Window)
}

func (c *Counter) unix() int64 {
	if c.now != nil {
		return c.now()
	}
	return time.Now().Unix()
}

func (c *Counter) advance(now int64) {
	if c.epoch == 0 {
		c.epoch = now
		return
	}
	if now <= c.epoch {
		return
	}
	dt := now - c.epoch
	if dt >= Window {
		for i := range c.total {
			c.total[i] = 0
		}
		for i := range c.class {
			for j := range c.class[i] {
				c.class[i][j] = 0
			}
		}
	} else {
		for i := int64(1); i <= dt; i++ {
			slot := (c.epoch + i) % Window
			c.total[slot] = 0
			for k := range c.class {
				c.class[k][slot] = 0
			}
		}
	}
	c.epoch = now
}
