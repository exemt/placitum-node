package handoff

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const (
	DefaultPath = "/var/run/waf/verdict.sock"

	MaxBytes = 8 << 20

	readBuffer = 32 << 20

	// maxDescriptors is how many passed descriptors one datagram may carry.
	// The module sends at most one, the file with the record's attachments;
	// anything beyond that is closed unread.
	maxDescriptors = 4
)

// Handler gets one datagram: the record and, when the module attached objects
// to it, the open file holding them. The handler owns the file and closes it.
type Handler func(raw []byte, attach *os.File)

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
		oob := make([]byte, syscall.CmsgSpace(maxDescriptors*4))

		for {
			n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
			if err != nil {
				return
			}

			attach := descriptor(oob[:oobn])

			if n == 0 {
				if attach != nil {
					_ = attach.Close()
				}
				continue
			}

			payload := make([]byte, n)
			copy(payload, buf[:n])
			handle(payload, attach)
		}
	}()

	return func() error {
		err := c.Close()
		<-done
		_ = os.Remove(path)
		return err
	}, nil
}

// descriptor takes the first passed descriptor out of the control messages
// and closes the rest: a leaked descriptor would keep the module's file alive
// for as long as the agent runs.
func descriptor(oob []byte) *os.File {
	if len(oob) == 0 {
		return nil
	}

	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}

	var first *os.File

	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			if first == nil {
				first = os.NewFile(uintptr(fd), "waf-record")
				continue
			}

			_ = syscall.Close(fd)
		}
	}

	return first
}
