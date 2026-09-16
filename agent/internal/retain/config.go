package retain

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWorkers   = 4
	defaultQueue     = 1024
	defaultOpTimeout = 5 * time.Second
	defaultRedis     = "127.0.0.1:6379"
	defaultRegion    = "us-east-1"
)

type Config struct {
	Redis RedisConfig
	S3    S3Config

	Bucket map[string]string

	Workers   int
	Queue     int
	OpTimeout time.Duration

	Batch map[string]BatchPolicy
}

type BatchPolicy struct {
	Size    int
	Timeout time.Duration
}

func (b BatchPolicy) immediate() bool {
	return b.Size <= 1 && b.Timeout <= 0
}

func (b BatchPolicy) full(n int) bool {
	if n == 0 {
		return false
	}

	if b.immediate() {
		return true
	}

	return b.Size > 0 && n >= b.Size
}

type RedisConfig struct {
	Addr     string
	User     string
	Password string
	DB       int

	Nodes []string

	DialTimeout time.Duration
}

type S3Config struct {
	Endpoint    string
	Region      string
	Credentials string
	Access      string
	Secret      string
}

func (c *Config) Finish() error {
	c.normalize()

	if c.S3.Credentials != "" {
		if err := c.readCredentials(c.S3.Credentials); err != nil {
			return err
		}
	}

	if c.S3.Endpoint != "" && !c.enabled() {
		return fmt.Errorf(
			"WAF_RETAIN_S3_ENDPOINT is set but %s", c.missing())
	}

	return nil
}

func (c *Config) SetRedis(value string) error {
	return c.readRedis(value)
}

func (c Config) Enabled() bool { return c.enabled() }

func (c Config) enabled() bool {
	return c.missing() == ""
}

func (c Config) missing() string {
	switch {
	case c.S3.Endpoint == "":
		return "WAF_RETAIN_S3_ENDPOINT is empty"
	case c.S3.Access == "" || c.S3.Secret == "":
		return "WAF_RETAIN_S3_CREDENTIALS_FILE gave no credentials"
	case c.Bucket["headers"] == "" && c.Bucket["args"] == "" &&
		c.Bucket["body"] == "":
		return "no WAF_RETAIN_BUCKET_* is set"
	}

	return ""
}

func (c Config) node(hint string) string {
	if hint == "" || hint == c.Redis.Addr {
		return c.Redis.Addr
	}

	for _, node := range c.Redis.Nodes {
		if node == hint {
			return hint
		}
	}

	return c.Redis.Addr
}

func (c Config) redisAuth() redisAuth {
	return redisAuth{
		user:        c.Redis.User,
		password:    c.Redis.Password,
		db:          c.Redis.DB,
		dialTimeout: c.Redis.DialTimeout,
		opTimeout:   c.OpTimeout,
	}
}

func (c *Config) normalize() {
	if c.Bucket == nil {
		c.Bucket = map[string]string{}
	}

	if c.Redis.Addr == "" {
		c.Redis.Addr = defaultRedis
	}

	if c.Redis.DialTimeout <= 0 {
		c.Redis.DialTimeout = defaultOpTimeout
	}

	if c.S3.Region == "" {
		c.S3.Region = defaultRegion
	}

	if c.Workers <= 0 {
		c.Workers = defaultWorkers
	}

	if c.Queue <= 0 {
		c.Queue = defaultQueue
	}

	if c.OpTimeout <= 0 {
		c.OpTimeout = defaultOpTimeout
	}

	if c.Batch == nil {
		c.Batch = map[string]BatchPolicy{}
	}
}

func (c *Config) readRedis(value string) error {
	if value == "" {
		return nil
	}

	if !strings.Contains(value, "://") {
		c.Redis.Addr = value
		return nil
	}

	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("WAF_RETAIN_REDIS_URL: %w", err)
	}

	if u.Scheme != "redis" {
		return fmt.Errorf("WAF_RETAIN_REDIS_URL: unsupported scheme %q", u.Scheme)
	}

	c.Redis.Addr = u.Host

	if u.User != nil {
		c.Redis.User = u.User.Username()
		c.Redis.Password, _ = u.User.Password()
	}

	if db := strings.Trim(u.Path, "/"); db != "" {
		n, err := strconv.Atoi(db)
		if err != nil {
			return fmt.Errorf("WAF_RETAIN_REDIS_URL: bad database %q", db)
		}

		c.Redis.DB = n
	}

	return nil
}

func (c *Config) readCredentials(path string) error {
	if path == "" {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("WAF_RETAIN_S3_CREDENTIALS_FILE: %w", err)
	}

	defer f.Close()

	scan := bufio.NewScanner(f)

	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())

		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "[") {
			continue
		}

		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		switch name {
		case "aws_access_key_id", "access_key":
			c.S3.Access = value
		case "aws_secret_access_key", "secret_key":
			c.S3.Secret = value
		}
	}

	if err := scan.Err(); err != nil {
		return fmt.Errorf("WAF_RETAIN_S3_CREDENTIALS_FILE: %w", err)
	}

	return nil
}

func KnownKind(kind string) bool {
	switch kind {
	case "headers", "args", "body":
		return true
	}

	return false
}

func ParseBatch(s string) (BatchPolicy, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "off" {
		return BatchPolicy{}, nil
	}

	s = strings.ReplaceAll(s, ",", " ")

	var out BatchPolicy

	for _, field := range strings.Fields(s) {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			return BatchPolicy{}, fmt.Errorf("expected key=value, got %q", field)
		}

		switch name {

		case "size":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return BatchPolicy{}, fmt.Errorf("size: %q", value)
			}
			out.Size = n

		case "timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d < 0 {
				return BatchPolicy{}, fmt.Errorf("timeout: %q", value)
			}
			out.Timeout = d

		default:
			return BatchPolicy{}, fmt.Errorf("unknown option %q", name)
		}
	}

	return out, nil
}
