package handoff

import (
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestServeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdict.sock")

	got := make(chan []byte, 1)

	stop, err := Serve(path, func(b []byte) {
		got <- append([]byte(nil), b...)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}

	c, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	want := []byte(`{"rid":"abc","node":"edge-01","verdict":"deny","score_total":80}`)
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-got:
		if string(raw) != string(want) {
			t.Fatalf("got %s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// Запись с превью занимает мегабайты. Урезанный приёмный буфер отрезал бы
// хвост молча, на стороне читателя и без ошибки, поэтому проверяется самая
// длинная датаграмма, какую ядро вообще согласилось выпустить.
//
// Согласится оно не на MaxBytes: SO_SNDBUF молча урезается до
// net.core.wmem_max, и на машине с умолчаниями это сотни килобайт, а не восемь
// мегабайт. Это не расхождение агента с модулем, а условие эксплуатации —
// модуль сообщает о нём в лог при старте воркера, — но приёмная сторона обязана
// принять всё, что до неё дошло, независимо от того, сколько это оказалось.
func TestServeLargeDatagram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdict.sock")

	got := make(chan []byte, 1)

	stop, err := Serve(path, func(b []byte) {
		got <- append([]byte(nil), b...)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	addr, err := net.ResolveUnixAddr("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}

	c, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.SetWriteBuffer(MaxBytes); err != nil {
		t.Fatal(err)
	}

	size := writable(t, c)
	if size < 128<<10 {
		t.Fatalf("send buffer is unusably small: %d", size)
	}

	want := make([]byte, size)
	for i := range want {
		want[i] = byte('a' + i%26)
	}

	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-got:
		if len(raw) != len(want) {
			t.Fatalf("got %d bytes, want %d", len(raw), len(want))
		}
		if string(raw) != string(want) {
			t.Fatal("payload differs")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// writable — самая длинная датаграмма, которую ядро выпустит через этот сокет,
// но не длиннее MaxBytes. Считается по SO_SNDBUF, который Linux сообщает
// удвоенным: половина уходит на служебные структуры. Запас в килобайт — на
// заголовок skb, размер которого от нас не зависит.
func writable(t *testing.T, c *net.UnixConn) int {
	t.Helper()

	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	var sndbuf int

	if err := raw.Control(func(fd uintptr) {
		sndbuf, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET,
			syscall.SO_SNDBUF)
	}); err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	size := sndbuf/2 - 1024
	if size > MaxBytes-64 {
		size = MaxBytes - 64
	}

	return size
}
