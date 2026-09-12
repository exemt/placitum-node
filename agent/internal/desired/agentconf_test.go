package desired

import (
	"testing"
	"time"

	"github.com/exemt/placitum-node/agent/internal/retain"
)

func base() retain.Config {
	return retain.Config{
		S3: retain.S3Config{
			Endpoint:    "http://minio:9000",
			Region:      "us-east-1",
			Credentials: "/run/secrets/waf_s3_creds",
			Access:      "waf",
			Secret:      "wafwafwaf",
		},
		Bucket:    map[string]string{"body": "waf-bodies"},
		Batch:     map[string]retain.BatchPolicy{"body": {Size: 8, Timeout: 100 * time.Millisecond}},
		Workers:   4,
		Queue:     1024,
		OpTimeout: 5 * time.Second,
	}
}

func TestParseAgentConf(t *testing.T) {
	c, err := ParseAgentConf([]byte(`{
		"v":1,"kind":"agent-conf","rev":7,"sha256":"sha256:abc",
		"s3":{"endpoint":"http://s3:9000","buckets":{"headers":"h","body":"b"}},
		"archive":{"workers":8,"batch":{"body":{"size":16}}}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Rev != 7 || c.SHA256 != "sha256:abc" {
		t.Fatalf("rev/hash: %d %q", c.Rev, c.SHA256)
	}
	if c.S3.Buckets["headers"] != "h" || *c.Archive.Workers != 8 {
		t.Fatalf("body not parsed: %+v", c)
	}
}

func TestParseAgentConfRejects(t *testing.T) {
	rows := []string{
		`{"v":2,"kind":"agent-conf","rev":1,"sha256":"sha256:a"}`,
		`{"v":1,"kind":"nginx-pack","rev":1,"sha256":"sha256:a"}`,
		`{"v":1,"kind":"agent-conf","rev":0,"sha256":"sha256:a"}`,
		`{"v":1,"kind":"agent-conf","rev":1,"sha256":"abc"}`,
		`{"v":1,"kind":"agent-conf","rev":1,"sha256":"sha256:a","s3":{"buckets":{"cookies":"c"}}}`,
		`{"v":1,"kind":"agent-conf","rev":1,"sha256":"sha256:a","archive":{"batch":{"cookies":{}}}}`,
	}
	for _, raw := range rows {
		if _, err := ParseAgentConf([]byte(raw)); err == nil {
			t.Fatalf("accepted: %s", raw)
		}
	}
}

// Оверлей называет только то, что прислал контроллер. Всё остальное -- то, что
// дала нода: реквизиты, путь к секрету, адрес обменника.
func TestOverlayKeepsNodeSecrets(t *testing.T) {
	c, err := ParseAgentConf([]byte(`{
		"v":1,"kind":"agent-conf","rev":1,"sha256":"sha256:a",
		"s3":{"endpoint":"http://other:9000","buckets":{"headers":"waf-headers"}},
		"archive":{"queue":2048,"timeout_ms":7000,"batch":{"body":{"timeout_ms":250}}}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := c.Overlay(base())

	if got.S3.Access != "waf" || got.S3.Secret != "wafwafwaf" {
		t.Fatalf("credentials lost: %+v", got.S3)
	}
	if got.S3.Endpoint != "http://other:9000" {
		t.Fatalf("endpoint not applied: %q", got.S3.Endpoint)
	}
	// Регион контроллер не называл -- остаётся нодин.
	if got.S3.Region != "us-east-1" {
		t.Fatalf("region overwritten: %q", got.S3.Region)
	}
	// Бакет, названный документом, добавляется к уже известным ноде.
	if got.Bucket["headers"] != "waf-headers" || got.Bucket["body"] != "waf-bodies" {
		t.Fatalf("buckets: %+v", got.Bucket)
	}
	if got.Queue != 2048 || got.OpTimeout != 7*time.Second || got.Workers != 4 {
		t.Fatalf("archive: queue=%d timeout=%s workers=%d", got.Queue, got.OpTimeout, got.Workers)
	}
	// Размер корзины документ не трогал -- остаётся прежний.
	if got.Batch["body"].Size != 8 || got.Batch["body"].Timeout != 250*time.Millisecond {
		t.Fatalf("batch: %+v", got.Batch["body"])
	}
}

// Пустой документ ничего не гасит: «контроллер про это молчит» -- не «выключи».
func TestOverlayEmptyKeepsNode(t *testing.T) {
	c, err := ParseAgentConf(
		[]byte(`{"v":1,"kind":"agent-conf","rev":3,"sha256":"sha256:a"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := c.Overlay(base())

	if got.S3.Endpoint != "http://minio:9000" || got.Bucket["body"] != "waf-bodies" {
		t.Fatalf("node config lost: %+v", got)
	}
	if !got.Enabled() {
		t.Fatalf("archive turned off by an empty document")
	}
}

// Карты базы не должны меняться: на них работает уже поднятый пул.
func TestOverlayDoesNotTouchBase(t *testing.T) {
	b := base()
	c, err := ParseAgentConf([]byte(`{
		"v":1,"kind":"agent-conf","rev":1,"sha256":"sha256:a",
		"s3":{"buckets":{"body":"other-bucket"}},
		"archive":{"batch":{"body":{"size":64}}}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	_ = c.Overlay(b)

	if b.Bucket["body"] != "waf-bodies" || b.Batch["body"].Size != 8 {
		t.Fatalf("base mutated: %+v %+v", b.Bucket, b.Batch)
	}
}
