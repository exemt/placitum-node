/*
 * Тот же скользящий счётчик, но по маршрутам: имя сервера и путь, как их
 * записал модуль в `route` датаграммы.
 *
 * Ключ приходит из конфигурации nginx, а не из запроса: `server_name` -- это
 * первое имя блока `server {}`, а не заголовок Host, и `location` -- имя
 * блока, а не URI. Поэтому мощность ключа ограничена размером конфига, и
 * клиент её не раздувает. Потолок ниже -- страховка от патологического
 * конфига, а не от трафика.
 *
 * Молчащий маршрут из карты уходит: конфиг перечитывают, сервер переименовывают
 * и удаляют, и вечная строка "0 rps" на имени, которого больше нет, -- это не
 * наблюдение, а мусор.
 */

package rps

import (
	"sort"
	"sync"
)

// MaxRoutes -- потолок числа одновременно наблюдаемых маршрутов на ноде.
// Дальше новые ключи не заводятся: итог ноды считает отдельный счётчик, и
// он от этого не страдает.
const MaxRoutes = 512

// Route -- ключ маршрута. Пустое имя сервера модуль пишет как "_"
// (перехватчик по умолчанию), пустой location -- как "/".
//
// ID -- uuid пути из waf_route_id. Он входит в ключ: одно и то же имя блока
// на двух серверах без server_name -- два маршрута панели, и складывать их
// нельзя. Пусто у модуля без директивы, тогда ключ -- только имена.
type Route struct {
	Server   string `json:"server"`
	Location string `json:"location"`
	ID       string `json:"id,omitempty"`
}

// RouteRates -- строка кадра: маршрут и его темп за окно.
type RouteRates struct {
	Route
	RPS   float64     `json:"rps"`
	Codes StatusRates `json:"codes"`
}

// Routes -- карта счётчиков по маршрутам.
type Routes struct {
	mu   sync.Mutex
	rows map[Route]*Counter
	max  int
	now  func() int64

	// dropped -- сколько датаграмм не попало в разбор из-за потолка. Итог
	// ноды их видит; в разборе по маршрутам их нет, и молчать об этом нельзя.
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

// Dropped -- сколько датаграмм потолок съел за всё время.
func (r *Routes) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.dropped
}

/*
 * Snapshot -- разбор за окно. Молчащие маршруты не только не печатаются, но и
 * удаляются: пустое окно и есть признак того, что маршрута в конфиге больше
 * нет либо трафика на нём не было все десять секунд.
 *
 * Порядок -- по имени сервера и пути, а не по темпу: кадр читают глазами в
 * логе и сравнивают с предыдущим, и строка, прыгающая по списку от каждого
 * запроса, этому мешает.
 */
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

// evictSilent освобождает место под новый ключ. Вызывается под замком.
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
