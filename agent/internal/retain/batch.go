/*
 * Корзины архива: три независимых накопления PUT, по виду объекта.
 *
 * S3 не принимает несколько объектов одним запросом. Корзина не меняет провод
 * — она выбирает момент, когда вспышкой уйдут обычные PutObject. Заголовки
 * могут уехать, пока тело ещё копится: секции не ждут друг друга.
 *
 * Запись аудита — другое дело. Локаторы в ней должны быть уже архивными, и
 * публиковать её раньше, чем уедет последняя секция этого запроса, значит
 * соврать читателю. Поэтому запись стоит на парковке, пока не закроются все
 * её виды; корзины при этом живут своей жизнью.
 *
 * GET из обменника делается в момент вспышки, не в момент приёма: иначе корзина
 * держала бы мегабайты тел, пока копится соседний запрос. retain_ttl на это
 * рассчитан — таймаут корзины на порядки короче.
 */

package retain

import (
	"sync"
	"time"

	"github.com/exemt/placitum-node/agent/internal/audit"
)

type basketItem struct {
	park  *parking
	kind  string
	terms audit.Terms
}

type basket struct {
	pool   *Pool
	kind   string
	policy BatchPolicy
	store  *redisPool

	mu     sync.Mutex
	items  []basketItem
	timer  *time.Timer
	closed bool

	flushMu sync.Mutex
}

type parking struct {
	mu      sync.Mutex
	d       audit.Decision
	section audit.Store
	pending int
	trash   []moved
	touched bool
}

func newBasket(p *Pool, kind string, policy BatchPolicy) *basket {
	return &basket{
		pool:   p,
		kind:   kind,
		policy: policy,
		store:  newRedisPool(p.cfg.redisAuth()),
	}
}

func (b *basket) push(item basketItem) {
	b.mu.Lock()

	if b.closed {
		b.mu.Unlock()
		b.doFlush([]basketItem{item})
		return
	}

	b.items = append(b.items, item)

	if b.policy.full(len(b.items)) {
		items := b.takeLocked()
		b.mu.Unlock()
		b.doFlush(items)
		return
	}

	if b.policy.Timeout > 0 && b.timer == nil {
		b.timer = time.AfterFunc(b.policy.Timeout, b.onTimer)
	}

	b.mu.Unlock()
}

func (b *basket) onTimer() {
	b.mu.Lock()
	items := b.takeLocked()
	b.mu.Unlock()
	b.doFlush(items)
}

func (b *basket) closeAndFlush() {
	b.mu.Lock()
	b.closed = true
	items := b.takeLocked()
	b.mu.Unlock()
	b.doFlush(items)
	b.store.close()
}

func (b *basket) takeLocked() []basketItem {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	items := b.items
	b.items = nil

	return items
}

func (b *basket) doFlush(items []basketItem) {
	if len(items) == 0 {
		return
	}

	// Одна вспышка за раз на корзину: свой RESP-клиент не рассчитан на два
	// конвейера, а две вспышки одной секции и не должны обгонять друг друга.
	b.flushMu.Lock()
	defer b.flushMu.Unlock()

	for _, item := range items {
		start := time.Now()
		reason, done := b.pool.move(b.store, item.park.d, item.park.section,
			item.kind, item.terms)

		out := 0
		if reason == "" {
			out = done.size
		}

		b.pool.io.Add(uint64(done.size), uint64(out), reason != "",
			time.Since(start))
		item.park.complete(b.pool, b.store, item.kind, reason, done)
	}
}

func (p *parking) complete(pool *Pool, store *redisPool, kind, reason string,
	done moved) {

	p.mu.Lock()

	raw, ok := p.section.Locators[kind]
	if ok {
		if reason != "" {
			p.section.Locators[kind] = pool.mark(raw, reason, p.d.Ray)
		} else {
			p.section.Locators[kind] = pool.readdress(raw, done, p.d.Ray)
			p.trash = append(p.trash, done)
		}
		p.touched = true
	}

	p.pending--
	if p.pending > 0 {
		p.mu.Unlock()
		return
	}

	d := p.d
	trash := p.trash
	touched := p.touched
	section := p.section
	p.mu.Unlock()

	if touched {
		if value, err := section.Render(); err == nil {
			if raw, err := audit.SpliceStore(d.Raw, value); err == nil {
				d.Raw = raw
			} else {
				pool.log.Warn("archive: splice failed",
					"ray", d.Ray, "error", err.Error())
			}
		} else {
			pool.log.Warn("archive: store render failed",
				"ray", d.Ray, "error", err.Error())
		}
	}

	pool.emit(d)

	for _, item := range trash {
		if err := store.del(item.addr, item.key); err != nil {
			pool.log.Warn("archive: store cleanup failed",
				"ray", d.Ray, "key", item.key, "error", err.Error())
		}
	}
}

// enqueue разбирает запись и раскладывает виды по корзинам. GET/PUT здесь нет:
// Handle зовут из цикла сокета, а воркер только ставит в очередь вспышки.
func (p *Pool) enqueue(d audit.Decision) {
	section, err := audit.ParseStore(d.Raw)
	if err != nil {
		p.log.Warn("archive: store is unreadable",
			"ray", d.Ray, "error", err.Error())
		p.emit(d)
		return
	}

	park := &parking{d: d, section: section}

	for _, kind := range audit.Kinds {
		if _, ok := d.Archive[kind]; !ok {
			continue
		}
		if _, ok := section.Locators[kind]; !ok {
			continue
		}
		park.pending++
	}

	if park.pending == 0 {
		p.emit(d)
		return
	}

	for _, kind := range audit.Kinds {
		terms, ok := d.Archive[kind]
		if !ok {
			continue
		}
		if _, ok := section.Locators[kind]; !ok {
			continue
		}

		p.baskets[kind].push(basketItem{
			park:  park,
			kind:  kind,
			terms: terms,
		})
	}
}
