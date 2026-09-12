/*
 * Приём итога от модуля: unix datagram на ноде, не шина вердиктов.
 *
 * Модуль делает один sendto(MSG_DONTWAIT) и забывает. Агент читает, собирает
 * kind=request и пишет в WAF_AUDIT. Промах сокета — потеря аудита, не запроса.
 */

package handoff

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const (
	DefaultPath = "/var/run/waf/verdict.sock"

	// Потолок датаграммы. Обязан совпадать с NGX_HTTP_WAF_AUDIT_DGRAM_MAX
	// модуля: unixgram обрезает лишнее молча, без ошибки и на стороне
	// читателя, — то есть запись превратилась бы в обрывок JSON без единого
	// признака того, что она обрезана.
	//
	// Восемь мегабайт — не запас, а следствие: превью без размера означает
	// «весь объект», а весь объект ограничен только client_max_body_size.
	// Модуль проверяет сумму бюджетов против этого же числа на nginx -t,
	// поэтому расхождение здесь ломает контур молча и в одну сторону.
	MaxBytes = 8 << 20

	// Очередь приёма. Одной датаграммы теперь хватает, чтобы занять её
	// целиком: без явного размера всплеск на время одного GC агента вытеснил
	// бы соседние записи.
	readBuffer = 32 << 20
)

type Handler func([]byte)

// Opts — размеры одного приёмника. Нулевое поле означает «как у сокета
// вердиктов»: потолок записи аудита и очередь под неё.
//
// Отдельные размеры нужны потому, что сокетов на ноде теперь два и датаграммы
// у них несопоставимы. Строка лога — это килобайты, и держать под неё тот же
// восьмимегабайтный буфер приёма, что под превью тела, значит занять память
// под запись, которой такого размера не бывает.
type Opts struct {
	// Max — потолок одной датаграммы. Больше — ядро обрежет молча.
	Max int
	// ReadBuffer — очередь приёма сокета (SO_RCVBUF).
	ReadBuffer int
}

// Serve слушает path и вызывает handle на каждый datagram. Сокет 0666:
// воркер nginx — другой uid. Close останавливает цикл и снимает файл.
func Serve(path string, handle Handler) (func() error, error) {
	return ServeOpts(path, Opts{}, handle)
}

// ServeOpts — то же самое со своими размерами приёмника.
func ServeOpts(path string, o Opts, handle Handler) (func() error, error) {
	if path == "" {
		path = DefaultPath
	}

	if o.Max <= 0 {
		o.Max = MaxBytes
	}

	if o.ReadBuffer <= 0 {
		o.ReadBuffer = readBuffer
	}

	if handle == nil {
		return nil, fmt.Errorf("handoff handler is nil")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	_ = os.Remove(path)

	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		return nil, err
	}

	c, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0o666); err != nil {
		c.Close()
		_ = os.Remove(path)
		return nil, err
	}

	// Неудача не повод не стартовать: ядро могло срезать размер до
	// net.core.rmem_max, и агент с меньшей очередью полезнее, чем его
	// отсутствие.
	_ = c.SetReadBuffer(o.ReadBuffer)

	done := make(chan struct{})

	go func() {
		defer close(done)

		buf := make([]byte, o.Max)

		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}

			if n == 0 {
				continue
			}

			payload := make([]byte, n)
			copy(payload, buf[:n])
			handle(payload)
		}
	}()

	return func() error {
		err := c.Close()
		<-done
		_ = os.Remove(path)
		return err
	}, nil
}
