package handoff

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const (
	DefaultPath = "/var/run/waf/verdict.sock"

	MaxBytes = 8 << 20

	readBuffer = 32 << 20
)

type Handler func([]byte)

type Opts struct {
	Max        int
	ReadBuffer int
}

func Serve(path string, handle Handler) (func() error, error) {
	return ServeOpts(path, Opts{}, handle)
}

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
