/*
 * Логи nginx: второй unix-сокет ноды и публикатор kind=log в WAF_LOG.
 *
 * nginx умеет писать в syslog сам (`access_log syslog:server=unix:…`), поэтому
 * ни модуля, ни хвоста файла здесь нет: агент открывает datagram-сокет, а
 * nginx кладёт в него строку в тот же момент, что и в файл. Промах сокета —
 * потеря строки лога, не запроса: nginx на unixgram не блокируется.
 *
 * Своя пачка, а не сообщение на строку: access-лог на тысяче запросов в
 * секунду — это тысяча публикаций в секунду с ноды, из которых каждая несёт
 * двести байт полезного. Пачка режется по трём границам сразу — числу строк,
 * объёму и времени, — и первая же сработавшая её отправляет.
 *
 * Отдельный поток, а не waf.audit.>: у логов другой темп и другая цена
 * потери, и всплеск access-лога не должен задерживать разбор аудита общим
 * consumer'ом.
 */

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

	// DefaultPath — сокет логов. Не тот же, что у вердиктов: там запись
	// аудита, здесь строка текста, и путать их в одном приёмнике значило бы
	// разбирать каждую датаграмму дважды, чтобы понять, что приехало.
	DefaultPath = "/var/run/waf/log.sock"

	// Потолок датаграммы. Сам nginx режет строку примерно на двух килобайтах
	// (NGX_SYSLOG_MAX_STR), шестнадцать — запас на длинный access-формат.
	MaxBytes = 16 << 10

	// Очередь приёма. Строки короткие, поэтому четырёх мегабайт хватает на
	// десятки тысяч непрочитанных: столько накапливается разве что на время
	// паузы GC.
	readBuffer = 4 << 20

	// Границы пачки. Пятьсот строк по паре килобайт — это ещё далеко от
	// max_payload шины, а четверть мегабайта закрывает случай длинных строк.
	maxLines = 500
	maxSize  = 256 << 10

	// Темп отправки при редком логе. Двести миллисекунд — задержка, которой
	// в журнале не видно, и она же не даёт держать строку в памяти агента,
	// пока не наберётся пачка.
	flushEvery = 200 * time.Millisecond

	// Потолок буфера при недоступной шине. Дальше выбрасываем самые старые:
	// логи — не аудит, и расти без границы агенту здесь нельзя.
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

// batch — то, что уезжает одним сообщением. Writer на конверте, а не на каждой
// строке: пачку собирает одна нода, и повторять её имя пятьсот раз незачем.
type batch struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Writer string `json:"writer"`
	Lines  []Line `json:"lines"`
}

// Sink копит строки и отправляет их пачками. Публикация идёт из своей
// горутины: читатель сокета не должен ждать шину.
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

// Add кладёт строку в пачку. Не блокирует и не ошибается: сокет читается тем
// же вызовом, и остановка здесь означала бы переполнение очереди приёма.
func (s *Sink) Add(line Line) {
	s.mu.Lock()

	s.pending = append(s.pending, line)
	s.size += len(line.Text) + 64

	/*
	 * Шина недоступна дольше, чем помещается в буфер. Выбрасываем голову, а
	 * не хвост: свежая строка объясняет, что происходит сейчас, и она нужнее
	 * той, что уже не уехала минуту назад.
	 */
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

// Dropped — сколько строк выброшено переполнением буфера за всё время.
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

// Close добивает накопленное и останавливает отправку.
func (s *Sink) Close() {
	s.once.Do(func() {
		close(s.stop)
		<-s.done
	})
}

/*
 * Serve поднимает сокет логов и подключает к нему пачку. Возвращает остановку
 * сокета и сам приёмник: пульс спрашивает у него темп и потери.
 */
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

// Ensure создаёт поток логов, если его ещё нет. Конфиг совпадает с
// tests/streams/streams.sh.
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
