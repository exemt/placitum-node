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
	// conf -- отпечаток боевого файла, который лежит на ноде сейчас. Едет
	// вместе с остальным под одним замком: кадр с новым поколением и старым
	// отпечатком показал бы расхождение там, где его нет.
	conf string
}

/*
NewApplied -- состояние без поколения, но с отпечатком того, что уже лежит на
диске. Затравка нужна и там, где раскатка выключена: воркеры работают по файлу
ноды, и сравнивать их с пустотой значит прятать колонку на исправном флоте.
Файла нет -- пустая строка, и колонки не будет.
*/
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
