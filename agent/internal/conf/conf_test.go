package conf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/exemt/placitum-node/agent/internal/retain"
)

const sample = `
node {
    id           edge-01
    key          /run/secrets/waf_node_key
    data         /var/lib/waf/agent
    heartbeat    4s
    verdict_sock /var/run/waf/verdict.sock
}

nats {
    url nats://nats:4222
}

redis {
    url   redis://redis:6379
    nodes 10.0.2.11:6379 10.0.2.12:6379
}

s3 {
    endpoint    http://minio:9000
    region      us-east-1
    credentials /run/secrets/waf_s3_creds
    bucket headers waf-headers
    bucket args    waf-args
    bucket body    waf-bodies
}

archive {
    workers 4
    queue   1024
    timeout 5s
    batch headers size=32 timeout=50ms
    batch args    off
    batch body    size=8 timeout=100ms
}

nginx {
    bin       nginx
    conf_dir  /etc/nginx
    store_dir /var/lib/waf/store
}
`

func TestParseShippedFile(t *testing.T) {
	text, err := os.ReadFile("../../agent.conf")
	if err != nil {
		t.Fatal(err)
	}

	c := blank()
	if err := parse(&c, string(text), "agent.conf"); err != nil {
		t.Fatal(err)
	}

	if c.NATS != "nats://nats:4222" || c.Retain.S3.Endpoint != "http://minio:9000" {
		t.Fatalf("shipped file: nats=%q s3=%q", c.NATS, c.Retain.S3.Endpoint)
	}

	// Обменник и внутренний Redis -- разные экземпляры: архив ходит в первый,
	// блобы поколения лежат во втором.
	if c.RedisURL != "redis://redis:6379" || c.RedisInternalURL != "redis://redis-internal:6379" {
		t.Fatalf("shipped redis: url=%q internal=%q", c.RedisURL, c.RedisInternalURL)
	}

	if c.Retain.Redis.Addr != "redis:6379" {
		t.Fatalf("retain must stay on the exchange: %+v", c.Retain.Redis)
	}

	if c.Retain.Batch["body"].Size != 8 {
		t.Fatalf("shipped body batch: %+v", c.Retain.Batch["body"])
	}
}

func TestParseSample(t *testing.T) {
	c := blank()
	if err := parse(&c, sample, "agent.conf"); err != nil {
		t.Fatal(err)
	}

	if c.NodeID != "edge-01" || c.NATS != "nats://nats:4222" {
		t.Fatalf("node/nats: %+v", c)
	}

	if c.Retain.S3.Endpoint != "http://minio:9000" ||
		c.Retain.S3.Credentials != "/run/secrets/waf_s3_creds" {
		t.Fatalf("s3: %+v", c.Retain.S3)
	}

	if c.Retain.Bucket["headers"] != "waf-headers" ||
		c.Retain.Bucket["body"] != "waf-bodies" {
		t.Fatalf("buckets: %v", c.Retain.Bucket)
	}

	h := c.Retain.Batch["headers"]
	if h.Size != 32 || h.Timeout != 50*time.Millisecond {
		t.Fatalf("headers batch: %+v", h)
	}

	if c.Retain.Batch["args"].Size != 0 || c.Retain.Batch["args"].Timeout != 0 {
		t.Fatalf("args should be off: %+v", c.Retain.Batch["args"])
	}

	if got := c.Retain.Redis.Nodes; len(got) != 2 || got[0] != "10.0.2.11:6379" {
		t.Fatalf("nodes: %v", got)
	}
}

// Блок redis из inspector.conf -- с точками с запятой -- читается агентом как
// есть: одна форма адресов на весь контур.
func TestParseRedisBlockInspectorForm(t *testing.T) {
	c := blank()
	src := "redis {\n    url       redis://redis:6379;\n    internal  redis://redis-internal:6379;\n}\n"
	if err := parse(&c, src, "agent.conf"); err != nil {
		t.Fatal(err)
	}

	if c.RedisURL != "redis://redis:6379" || c.RedisInternalURL != "redis://redis-internal:6379" {
		t.Fatalf("redis: url=%q internal=%q", c.RedisURL, c.RedisInternalURL)
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	c := blank()
	err := parse(&c, "s3 {\n    endpoint http://minio:9000\n    flavour minio\n}\n", "x.conf")
	if err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestParseRejectsUnclosed(t *testing.T) {
	c := blank()
	err := parse(&c, "nats {\n    url nats://nats:4222\n", "x.conf")
	if err == nil {
		t.Fatal("unclosed block accepted")
	}
}

func TestParseOneLineBlock(t *testing.T) {
	c := blank()
	err := parse(&c, "nats { url nats://nats:4222 }\nnode { id edge-01 }\n", "x.conf")
	if err != nil {
		t.Fatal(err)
	}
	if c.NATS != "nats://nats:4222" || c.NodeID != "edge-01" {
		t.Fatalf("%q %q", c.NATS, c.NodeID)
	}
}

func TestParseHashComment(t *testing.T) {
	c := blank()
	err := parse(&c, "nats {\n    url nats://nats:4222 # stand\n}\n", "x.conf")
	if err != nil {
		t.Fatal(err)
	}
	if c.NATS != "nats://nats:4222" {
		t.Fatalf("comment ate the value: %q", c.NATS)
	}
}

func TestLoadFileThenNodeEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")

	creds := filepath.Join(dir, "s3.creds")
	if err := os.WriteFile(creds, []byte("aws_access_key_id=k\naws_secret_access_key=s\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	text := `
s3 {
    endpoint    http://minio:9000
    credentials ` + creds + `
    bucket body waf-bodies
}
nats { url nats://nats:4222 }
node { id edge-01 }
`
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("WAF_AGENT_CONFIG", path)
	t.Setenv("WAF_NODE_ID", "edge-02")
	t.Setenv("WAF_RETAIN_S3_CREDENTIALS_FILE", creds)

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if got.NodeID != "edge-02" {
		t.Fatalf("env must override node id: %q", got.NodeID)
	}
	if got.Path != path {
		t.Fatalf("path: %q", got.Path)
	}
	if got.Retain.S3.Access != "k" {
		t.Fatalf("credentials not read: %+v", got.Retain.S3)
	}
}

func blank() Config {
	return Config{
		Retain: retain.Config{
			Bucket: map[string]string{},
			Batch:  map[string]retain.BatchPolicy{},
		},
	}
}
