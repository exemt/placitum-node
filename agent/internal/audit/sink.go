/*
 * Пачка записей аудита вместо сообщения на запрос.
 *
 * Модуль отдаёт итог на unix-сокет по одной датаграмме на запрос, и раньше
 * ровно столько же уходило на шину: тридцать тысяч запросов в секунду -- это
 * тридцать тысяч публикаций в секунду с одной ноды, каждая по килобайту
 * полезного. Потребитель при этом вставляет в ClickHouse партиями, и партия
 * из одного сообщения -- прямая дорога к "too many parts".
 *
 * Устройство то же, что у пачки логов (internal/nginxlog): границы по числу
 * записей, по объёму и по времени, первая сработавшая отправляет. Отличие
 * одно и существенное: запись аудита дороже строки лога, поэтому переполнение
 * буфера считается и попадает в пульс, а не растворяется.
 *
 * Формат конверта пачки выбран так, чтобы потребителю не пришлось учить новый
 * разбор записи: items -- это ровно те байты, которые уезжали отдельными
 * сообщениями, элемент в элемент.
 */

package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-node/agent/internal/flow"
)

// KindBatch -- вид сообщения-пачки. Соседствует с Kind по потоку и субъекту:
// пачка едет туда же, куда ехала бы каждая её запись.
const KindBatch = "batch"

const (
	/*
	 * Границы пачки. Записи по килобайту-полутора, поэтому двести пятьдесят
	 * шесть штук -- это заметно меньше max_payload шины даже на длинных
	 * записях, а полмегабайта закрывают случай, когда они длиннее ожидаемого.
	 */
	maxItems = 256
	maxSize  = 512 << 10

	/*
	 * Темп отправки при редком трафике. Пятьдесят миллисекунд -- задержка,
	 * которой в журнале не видно, и она же не даёт держать запись в памяти
	 * агента, пока не наберётся пачка.
	 */
	flushEvery = 50 * time.Millisecond

	/*
	 * Потолок буфера при недоступной шине. Аудит дороже лога, поэтому запас
	 * больше, но не бесконечный: агент, растущий без границы, меняет потерю
	 * аудита на потерю ноды.
	 */
	maxPending = 50000
)

// item -- готовая к отправке запись и узел, на субъект которого она едет.
// Узел хранится рядом, а не берётся у sink: субъект считается по записи, и
// агент, увидевший чужой узел, не должен отправить её не туда.
type item struct {
	node string
	body []byte
}

// envelope -- конверт пачки. items уезжают как есть: каждый элемент -- это
// запись ровно в том виде, в каком её собрал Envelope.
type envelope struct {
	V     int               `json:"v"`
	Kind  string            `json:"kind"`
	Node  string            `json:"node,omitempty"`
	Items []json.RawMessage `json:"items"`
}

// Sink копит записи и отправляет их пачками. Публикация идёт из своей
// горутины: читатель сокета вердиктов не должен ждать шину.
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

/*
 * Add кладёт запись в пачку. Не блокирует и не ошибается: вызывающий читает
 * сокет вердиктов той же горутиной, и остановка здесь означала бы переполнение
 * очереди приёма ядра -- то есть потерю записи вместо её задержки.
 *
 * Конверт дописывается здесь, а не при отправке: он зависит от записи, а не от
 * пачки, и ошибка разбора должна называть свою запись, а не всю пачку.
 */
func (s *Sink) Add(d Decision) error {
	if s == nil || s.nc == nil || d.Ray == "" || d.Node == "" || d.Verdict == "" {
		return nil
	}

	// Узел уже есть в теле, если его прислал модуль: повторять поле нельзя,
	// разбор берёт последнее, и запись зависела бы от порядка.
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

	/*
	 * Шина недоступна дольше, чем помещается в буфер. Выбрасываем голову, а
	 * не хвост: свежая запись объясняет, что происходит сейчас. Потеря видна
	 * в Dropped и уезжает в пульс -- молча терять аудит нельзя.
	 */
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

// Dropped -- сколько записей выброшено переполнением буфера за всё время.
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

/*
 * publish отправляет взятое, разложив по узлам. Узлов у одного агента ровно
 * один, но субъект считается по записи, и складывать чужую запись в свой
 * субъект нельзя даже тогда, когда это невозможно: цена проверки -- одна
 * карта на пачку, цена ошибки -- потерянная в чужой ветке запись.
 */
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

// groupByNode раскладывает взятое по узлам, сохраняя порядок первого
// появления: пачки должны уходить предсказуемо, а не в порядке обхода карты.
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

/*
 * pack собирает конверт пачки. Сборка руками, а не json.Marshal по записям:
 * тело каждой записи уже готово, и повторный разбор с пересборкой менял бы
 * представление чисел и порядок полей -- то самое, что Envelope бережёт.
 */
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

// Close добивает накопленное и останавливает отправку. Очередь дописывается
// целиком: в ней записи, которые иначе не уедут вовсе.
func (s *Sink) Close() {
	if s == nil {
		return
	}

	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

// Unpack разбирает пачку на записи. Живёт рядом с упаковкой, чтобы формат
// проверялся с обеих сторон одним тестом; потребитель на другом языке читает
// items сам.
func Unpack(payload []byte) ([]json.RawMessage, bool) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, false
	}

	var env envelope

	if err := json.Unmarshal(payload, &env); err != nil || env.Kind != KindBatch {
		return nil, false
	}

	return env.Items, true
}
