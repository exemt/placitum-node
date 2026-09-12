package retain

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/exemt/placitum-node/agent/internal/audit"
)

func switchCfg() Config {
	return Config{
		S3: S3Config{
			Endpoint: "http://minio:9000",
			Region:   "us-east-1",
			Access:   "waf",
			Secret:   "wafwafwaf",
		},
		Bucket:    map[string]string{"body": "waf-bodies"},
		Batch:     map[string]BatchPolicy{},
		Workers:   1,
		Queue:     8,
		OpTimeout: time.Second,
	}
}

// Запись без архива проходит через замену настройки: подмена пула не должна
// быть заметна тому, кто зовёт Handle.
func TestSwitchKeepsPublishing(t *testing.T) {
	var mu sync.Mutex
	seen := 0

	s := NewSwitch(switchCfg(), func(audit.Decision) error {
		mu.Lock()
		seen++
		mu.Unlock()
		return nil
	}, nil)
	defer s.Close()

	s.Handle(audit.Decision{Raw: json.RawMessage(`{}`)})

	next := switchCfg()
	next.Workers = 2
	if err := s.Apply(next); err != nil {
		t.Fatalf("apply: %v", err)
	}

	s.Handle(audit.Decision{Raw: json.RawMessage(`{}`)})

	if s.Config().Workers != 2 {
		t.Fatalf("config not swapped: %d", s.Config().Workers)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen != 2 {
		t.Fatalf("published %d records, want 2", seen)
	}
}

// Настройка, которую нода не может собрать, оставляет прежнюю в силе: у
// контроллера нет реквизитов, и его документ не должен гасить архив.
func TestSwitchRejectsBrokenConfig(t *testing.T) {
	s := NewSwitch(switchCfg(), func(audit.Decision) error { return nil }, nil)
	defer s.Close()

	broken := switchCfg()
	broken.S3.Access = ""
	broken.S3.Secret = ""

	if err := s.Apply(broken); err == nil {
		t.Fatalf("broken config accepted")
	}
	if !s.Enabled() || s.Config().S3.Access != "waf" {
		t.Fatalf("live config damaged: %+v", s.Config().S3)
	}
}
