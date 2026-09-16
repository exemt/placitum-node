package id

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const fileName = "agent.id"

func Load(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fileName)
	raw, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(raw))
		if id != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	id, err := newUUID()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
