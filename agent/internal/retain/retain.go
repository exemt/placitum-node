package retain

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/exemt/placitum-node/agent/internal/audit"
	"github.com/exemt/placitum-shared/flow"
)

const (
	reasonExpired  = "expired"
	reasonEmpty    = "empty"
	reasonOverload = "overload"
	reasonError    = "archive_error"
)

type Publisher func(audit.Decision) error

type Pool struct {
	cfg     Config
	s3      *s3Client
	log     *slog.Logger
	publish Publisher
	io      *flow.Counter

	jobs chan audit.Decision
	wg   sync.WaitGroup

	baskets map[string]*basket

	sweep   chan []moved
	sweepWG sync.WaitGroup

	once sync.Once
}

func NewShared(
	cfg Config,
	publish Publisher,
	log *slog.Logger,
	io *flow.Counter,
) *Pool {
	cfg.normalize()

	if log == nil {
		log = slog.Default()
	}
	if io == nil {
		io = flow.New()
	}

	p := &Pool{
		cfg:     cfg,
		log:     log,
		publish: publish,
		io:      io,
		jobs:    make(chan audit.Decision, cfg.Queue),
		sweep:   make(chan []moved, cfg.Queue),
	}

	p.sweepWG.Add(1)
	go p.clean()

	if cfg.enabled() {
		p.s3 = &s3Client{
			endpoint: strings.TrimRight(cfg.S3.Endpoint, "/"),
			region:   cfg.S3.Region,
			access:   cfg.S3.Access,
			secret:   cfg.S3.Secret,
			http: &http.Client{
				Timeout: cfg.OpTimeout,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: cfg.Workers,
					IdleConnTimeout:     90 * time.Second,
				},
			},
		}

		p.baskets = make(map[string]*basket, len(audit.Kinds))
		for _, kind := range audit.Kinds {
			p.baskets[kind] = newBasket(p, kind, cfg.Batch[kind])
		}

		for i := 0; i < cfg.Workers; i++ {
			p.wg.Add(1)
			go p.work()
		}
	}

	return p
}

func (p *Pool) Handle(d audit.Decision) {
	if len(d.Archive) == 0 {
		p.emit(d)
		return
	}

	if p.s3 == nil {
		p.degrade(d, reasonError, "archive is not configured")
		return
	}

	select {
	case p.jobs <- d:
	default:
		p.degrade(d, reasonOverload, "archive queue is full")
	}
}

func (p *Pool) Close() {
	p.once.Do(func() {
		close(p.jobs)
		p.wg.Wait()
		for _, kind := range audit.Kinds {
			if b := p.baskets[kind]; b != nil {
				b.closeAndFlush()
			}
		}
		close(p.sweep)
		p.sweepWG.Wait()
	})
}

func (p *Pool) work() {
	defer p.wg.Done()

	for d := range p.jobs {
		p.enqueue(d)
	}
}

func (p *Pool) clean() {
	defer p.sweepWG.Done()

	store := newRedisPool(p.cfg.redisAuth())
	defer store.close()

	for batch := range p.sweep {
		for _, item := range batch {
			if item.key == "" {
				continue
			}

			if err := store.del(item.addr, item.key); err != nil {
				p.log.Warn("archive: store cleanup failed",
					"key", item.key, "error", err.Error())
			}
		}
	}
}

type moved struct {
	object  string
	expires int64
	key     string
	addr    string
	size    int
	trimmed bool
}

func (p *Pool) move(store *redisPool, d audit.Decision, section audit.Store,
	kind string, terms audit.Terms) (string, moved) {

	bucket := p.cfg.Bucket[kind]
	if bucket == "" {
		p.log.Warn("archive: no bucket for kind", "ray", d.Ray, "kind", kind)
		return reasonError, moved{}
	}

	var (
		data      []byte
		addr, key string
	)

	if attached, ok := d.Attached[kind]; ok {
		// The object rode with the record: nothing to fetch, no key to
		// clean up afterwards.
		data = attached

	} else {
		loc, ok := section.Locate(kind)
		if !ok {
			p.log.Warn("archive: locator has no address", "ray", d.Ray, "kind", kind)
			return reasonError, moved{}
		}

		addr = p.cfg.node(loc.Hint)
		key = loc.Key

		var err error

		data, err = store.get(addr, key)
		if errors.Is(err, ErrMissing) {
			return reasonExpired, moved{}
		}
		if err != nil {
			p.log.Warn("archive: store read failed",
				"ray", d.Ray, "kind", kind, "node", addr, "error", err.Error())
			return reasonError, moved{}
		}
	}

	if len(data) == 0 {
		return reasonEmpty, moved{}
	}

	filtered, err := applyTerms(kind, data, terms)
	if err != nil {
		p.log.Warn("archive: list filter failed",
			"ray", d.Ray, "kind", kind, "error", err.Error())
		return reasonError, moved{}
	}
	data = filtered

	if len(data) == 0 {
		return reasonEmpty, moved{}
	}

	data, trimmed := cutToLimit(kind, data, terms.Limit)

	object := objectName(d, kind)

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.OpTimeout)
	defer cancel()

	expires, err := p.s3.put(ctx, bucket, object, data, retainTag(terms.TTL))
	if err != nil {
		p.log.Warn("archive: put failed",
			"ray", d.Ray, "kind", kind, "bucket", bucket, "object", object,
			"error", err.Error())
		return reasonError, moved{size: len(data)}
	}

	p.log.Info("archive: put ok",
		"ray", d.Ray, "kind", kind, "bucket", bucket, "object", object,
		"size", len(data), "trimmed", trimmed, "expires_at", expires)

	return "", moved{
		object:  object,
		expires: expires,
		key:     key,
		addr:    addr,
		size:    len(data),
		trimmed: trimmed,
	}
}

func (p *Pool) degrade(d audit.Decision, reason, why string) {
	p.log.Warn("archive: skipped", "ray", d.Ray, "reason", why)

	section, err := audit.ParseStore(d.Raw)
	if err != nil {
		p.emit(d)
		return
	}

	var orphans []moved

	for _, kind := range audit.Kinds {
		if _, ok := d.Archive[kind]; !ok {
			continue
		}

		raw, ok := section.Locators[kind]
		if !ok {
			continue
		}

		if loc, ok := section.Locate(kind); ok {
			orphans = append(orphans, moved{
				key:  loc.Key,
				addr: p.cfg.node(loc.Hint),
			})
		}

		section.Locators[kind] = p.mark(raw, reason, d.Ray)
	}

	if value, err := section.Render(); err == nil {
		if raw, err := audit.SpliceStore(d.Raw, value); err == nil {
			d.Raw = raw
		}
	}

	p.emit(d)

	if len(orphans) == 0 {
		return
	}

	select {
	case p.sweep <- orphans:
	default:
		p.log.Warn("archive: cleanup queue is full", "ray", d.Ray)
	}
}

func (p *Pool) emit(d audit.Decision) {
	if p.publish == nil {
		return
	}

	if err := p.publish(d); err != nil {
		p.log.Warn("audit publish failed", "ray", d.Ray, "error", err.Error())
	}
}

func (p *Pool) mark(raw json.RawMessage, reason, ray string) json.RawMessage {
	out, err := audit.Unreachable(raw, reason)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return raw
	}

	return out
}

func (p *Pool) readdress(raw json.RawMessage, done moved, ray string) json.RawMessage {
	out, err := audit.Readdress(raw, "archive", "s3", done.object, done.expires)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return raw
	}

	if !done.trimmed {
		return out
	}

	marked, err := audit.Trimmed(out, done.size)
	if err != nil {
		p.log.Warn("archive: locator is unreadable",
			"ray", ray, "error", err.Error())
		return out
	}

	return marked
}

func objectName(d audit.Decision, kind string) string {
	ts, err := time.Parse(time.RFC3339, d.TS)
	if err != nil {
		ts = time.Now()
	}

	ts = ts.UTC()

	node := d.Node
	if node == "" {
		node = "unknown"
	}

	name := d.Ray
	if d.Phase != "" && d.Phase != "request" {
		name += "." + d.Phase
	}
	if d.Phase == "frame" && d.FrameDirection != "" {
		name += "." + d.FrameDirection + "." + strconv.FormatUint(d.FrameSeq, 10)
	}

	return ts.Format("2006/01/02") + "/" + node + "/" +
		name + "." + audit.Suffix[kind]
}

func retainTag(ttl int64) string {
	if ttl <= 0 {
		return ""
	}

	return "waf-retain-ttl=" + strconv.FormatInt(ttl, 10)
}
