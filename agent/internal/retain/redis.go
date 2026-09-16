package retain

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

var ErrMissing = errors.New("retain: key is gone")

type redisAuth struct {
	user     string
	password string
	db       int

	dialTimeout time.Duration
	opTimeout   time.Duration
}

type redisConn struct {
	c  net.Conn
	br *bufio.Reader
}

type redisPool struct {
	auth  redisAuth
	conns map[string]*redisConn
}

func newRedisPool(auth redisAuth) *redisPool {
	return &redisPool{auth: auth, conns: map[string]*redisConn{}}
}

func (p *redisPool) close() {
	for addr, conn := range p.conns {
		_ = conn.c.Close()
		delete(p.conns, addr)
	}
}

func (p *redisPool) get(addr, key string) ([]byte, error) {
	conn, err := p.conn(addr)
	if err != nil {
		return nil, err
	}

	data, err := p.call(addr, conn, '$', "GET", key)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, ErrMissing
	}

	return data, nil
}

func (p *redisPool) del(addr, key string) error {
	conn, err := p.conn(addr)
	if err != nil {
		return err
	}

	_, err = p.call(addr, conn, ':', "DEL", key)

	return err
}

func (p *redisPool) call(addr string, conn *redisConn, want byte,
	args ...string) ([]byte, error) {

	deadline := time.Now().Add(p.auth.opTimeout)

	if err := conn.c.SetDeadline(deadline); err != nil {
		p.drop(addr)
		return nil, err
	}

	if err := writeCommand(conn.c, args...); err != nil {
		p.drop(addr)
		return nil, err
	}

	kind, data, err := readReply(conn.br)
	if err != nil {
		p.drop(addr)
		return nil, err
	}

	if kind != want {
		p.drop(addr)
		return nil, fmt.Errorf("retain: %s answered %q", args[0], kind)
	}

	return data, nil
}

func (p *redisPool) conn(addr string) (*redisConn, error) {
	if conn, ok := p.conns[addr]; ok {
		return conn, nil
	}

	c, err := net.DialTimeout("tcp", addr, p.auth.dialTimeout)
	if err != nil {
		return nil, err
	}

	conn := &redisConn{c: c, br: bufio.NewReader(c)}

	if err := p.handshake(conn); err != nil {
		_ = c.Close()
		return nil, err
	}

	p.conns[addr] = conn

	return conn, nil
}

func (p *redisPool) drop(addr string) {
	if conn, ok := p.conns[addr]; ok {
		_ = conn.c.Close()
		delete(p.conns, addr)
	}
}

func (p *redisPool) handshake(conn *redisConn) error {
	if err := conn.c.SetDeadline(time.Now().Add(p.auth.dialTimeout)); err != nil {
		return err
	}

	if p.auth.password != "" {
		user := p.auth.user
		if user == "" {
			user = "default"
		}

		if err := writeCommand(conn.c, "AUTH", user, p.auth.password); err != nil {
			return err
		}

		if _, _, err := expect(conn.br, '+'); err != nil {
			return err
		}
	}

	if p.auth.db != 0 {
		if err := writeCommand(conn.c, "SELECT",
			strconv.Itoa(p.auth.db)); err != nil {
			return err
		}

		if _, _, err := expect(conn.br, '+'); err != nil {
			return err
		}
	}

	return nil
}

func expect(br *bufio.Reader, want byte) (byte, []byte, error) {
	kind, data, err := readReply(br)
	if err != nil {
		return 0, nil, err
	}

	if kind != want {
		return 0, nil, fmt.Errorf("retain: unexpected reply %q", kind)
	}

	return kind, data, nil
}

func writeCommand(w net.Conn, args ...string) error {
	buf := make([]byte, 0, 64)

	buf = append(buf, '*')
	buf = strconv.AppendInt(buf, int64(len(args)), 10)
	buf = append(buf, '\r', '\n')

	for _, arg := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(arg)), 10)
		buf = append(buf, '\r', '\n')
		buf = append(buf, arg...)
		buf = append(buf, '\r', '\n')
	}

	_, err := w.Write(buf)

	return err
}

func readReply(br *bufio.Reader) (byte, []byte, error) {
	line, err := readLine(br)
	if err != nil {
		return 0, nil, err
	}

	if len(line) == 0 {
		return 0, nil, fmt.Errorf("retain: empty reply")
	}

	kind, body := line[0], line[1:]

	switch kind {

	case '+', ':':
		return kind, body, nil

	case '-':
		return kind, body, fmt.Errorf("retain: store said %q", body)

	case '$':
		n, err := strconv.Atoi(string(body))
		if err != nil {
			return 0, nil, fmt.Errorf("retain: bad bulk length %q", body)
		}

		if n < 0 {
			return kind, nil, nil
		}

		data := make([]byte, n+2)

		if _, err := io.ReadFull(br, data); err != nil {
			return 0, nil, err
		}

		return kind, data[:n], nil
	}

	return 0, nil, fmt.Errorf("retain: unknown reply type %q", kind)
}

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	for len(line) != 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}

	return line, nil
}
