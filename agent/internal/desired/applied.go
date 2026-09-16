package desired

import "sync"

const (
	ApplyOK       = "ok"
	ApplyFailed   = "apply_failed"
	Undecryptable = "undecryptable"
)

type Applied struct {
	mu    sync.RWMutex
	hash  string
	rev   int
	apply string
	conf  string
}

func NewApplied(confDir string) *Applied {
	return &Applied{conf: FingerprintFile(LiveConfPath(confDir))}
}

func (a *Applied) Snapshot() (hash string, rev int, apply string, conf string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.hash, a.rev, a.apply, a.conf
}

func (a *Applied) set(hash string, rev int, apply string, conf string) {
	a.mu.Lock()
	a.hash = hash
	a.rev = rev
	a.apply = apply
	a.conf = conf
	a.mu.Unlock()
}
