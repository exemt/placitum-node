package conf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/exemt/placitum-node/agent/internal/retain"
)

var blocks = map[string]bool{
	"node":       true,
	"nats":       true,
	"redis":      true,
	"s3":         true,
	"archive":    true,
	"nginx":      true,
	"controller": true,
}

func parse(c *Config, text, path string) error {
	p := &parser{cfg: c, path: path}

	for i, raw := range strings.Split(text, "\n") {
		p.line = i + 1
		if err := p.feed(raw); err != nil {
			return fmt.Errorf("%s:%d: %w", path, p.line, err)
		}
	}

	if p.block != "" {
		return fmt.Errorf("%s:%d: unclosed %s block", path, p.line, p.block)
	}

	return nil
}

type parser struct {
	cfg   *Config
	path  string
	block string
	line  int
}

func (p *parser) feed(raw string) error {
	line := stripComment(raw)
	if line == "" {
		return nil
	}

	// Точка с запятой в конце ключа допустима: блок redis пишется одинаково
	// в agent.conf и в inspector.conf, где она обязательна.
	line = strings.TrimSpace(strings.TrimSuffix(line, ";"))

	if line == "}" {
		if p.block == "" {
			return fmt.Errorf("unexpected }")
		}
		p.block = ""
		return nil
	}

	if i := strings.Index(line, "{"); i >= 0 {
		name := strings.TrimSpace(line[:i])
		rest := strings.TrimSpace(line[i+1:])
		if name == "" {
			return fmt.Errorf("block without a name")
		}
		if p.block != "" {
			return fmt.Errorf("nested blocks are not allowed")
		}
		if !blocks[name] {
			return fmt.Errorf("unknown block %q", name)
		}

		if strings.HasSuffix(rest, "}") {
			inner := strings.TrimSpace(strings.TrimSuffix(rest, "}"))
			if inner == "" {
				return nil
			}
			p.block = name
			err := p.apply(splitKey(inner))
			p.block = ""
			return err
		}

		if rest != "" {
			return fmt.Errorf("block %q: put keys on their own lines", name)
		}

		p.block = name
		return nil
	}

	if p.block == "" {
		return fmt.Errorf("key %q is outside a block", firstWord(line))
	}

	key, rest := splitKey(line)
	if key == "" {
		return fmt.Errorf("empty key")
	}

	return p.apply(key, rest)
}

func (p *parser) apply(key, rest string) error {
	if rest == "" {
		return fmt.Errorf("%s: missing value", key)
	}

	switch p.block {

	case "node":
		switch key {
		case "id":
			p.cfg.NodeID = rest
		case "key":
			p.cfg.NodeKey = rest
		case "data":
			p.cfg.DataDir = rest
		case "heartbeat":
			d, err := time.ParseDuration(rest)
			if err != nil || d <= 0 {
				return fmt.Errorf("heartbeat: expected a duration, got %q", rest)
			}
			p.cfg.Heartbeat = d
		case "verdict_sock":
			p.cfg.VerdictSock = rest
		case "log_sock":
			// off — не путь, а выключатель: на ноде, где логи собирает
			// кто-то другой, приёмник поднимать незачем.
			if rest == "off" {
				p.cfg.LogSock = ""
			} else {
				p.cfg.LogSock = rest
			}
		default:
			return unknown(key)
		}

	case "nats":
		if key != "url" {
			return unknown(key)
		}
		p.cfg.NATS = rest

	case "redis":
		switch key {
		case "url":
			p.cfg.RedisURL = rest
			if err := p.cfg.Retain.SetRedis(rest); err != nil {
				return err
			}
		case "internal":
			// Внутренний Redis контура: блобы поколения. Архив (retain) сюда
			// не ходит -- ему обменник из url.
			p.cfg.RedisInternalURL = rest
		case "nodes":
			p.cfg.RedisNodes = strings.Fields(rest)
			p.cfg.Retain.Redis.Nodes = append([]string(nil), p.cfg.RedisNodes...)
		default:
			return unknown(key)
		}

	case "s3":
		switch key {
		case "endpoint":
			p.cfg.Retain.S3.Endpoint = rest
		case "region":
			p.cfg.Retain.S3.Region = rest
		case "credentials":
			p.cfg.Retain.S3.Credentials = rest
		case "bucket":
			kind, name := splitKey(rest)
			if !retain.KnownKind(kind) {
				return fmt.Errorf("bucket: unknown kind %q", kind)
			}
			if name == "" {
				return fmt.Errorf("bucket %s: missing name", kind)
			}
			if p.cfg.Retain.Bucket == nil {
				p.cfg.Retain.Bucket = map[string]string{}
			}
			p.cfg.Retain.Bucket[kind] = name
		default:
			return unknown(key)
		}

	case "archive":
		switch key {
		case "workers":
			n, err := parsePositive(rest)
			if err != nil {
				return fmt.Errorf("workers: expected a positive number, got %q", rest)
			}
			p.cfg.Retain.Workers = n
		case "queue":
			n, err := parsePositive(rest)
			if err != nil {
				return fmt.Errorf("queue: expected a positive number, got %q", rest)
			}
			p.cfg.Retain.Queue = n
		case "timeout":
			d, err := time.ParseDuration(rest)
			if err != nil || d <= 0 {
				return fmt.Errorf("timeout: expected a duration, got %q", rest)
			}
			p.cfg.Retain.OpTimeout = d
		case "batch":
			kind, spec := splitKey(rest)
			if !retain.KnownKind(kind) {
				return fmt.Errorf("batch: unknown kind %q", kind)
			}
			policy, err := retain.ParseBatch(spec)
			if err != nil {
				return fmt.Errorf("batch %s: %w", kind, err)
			}
			if p.cfg.Retain.Batch == nil {
				p.cfg.Retain.Batch = map[string]retain.BatchPolicy{}
			}
			p.cfg.Retain.Batch[kind] = policy
		default:
			return unknown(key)
		}

	case "nginx":
		switch key {
		case "bin":
			p.cfg.NginxBin = rest
		case "conf":
			p.cfg.NginxConf = rest
		case "conf_dir":
			p.cfg.ConfDir = rest
		case "store_dir":
			p.cfg.StoreDir = rest
		case "manage":
			switch rest {
			case "on", "true", "yes", "1":
				p.cfg.NginxManage = true
			case "off", "false", "no", "0":
				p.cfg.NginxManage = false
			default:
				return fmt.Errorf("nginx manage: expected on or off, got %q", rest)
			}
		default:
			return unknown(key)
		}

	case "controller":
		switch key {
		case "url":
			p.cfg.ControllerURL = rest
		case "scope":
			p.cfg.Scope = rest
		default:
			return unknown(key)
		}

	default:
		return fmt.Errorf("internal: block %q", p.block)
	}

	return nil
}

func unknown(key string) error {
	return fmt.Errorf("unknown key %q", key)
}

func stripComment(s string) string {
	inQuote := false

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				s = s[:i]
			}
		}
	}

	return strings.TrimSpace(s)
}

func splitKey(s string) (string, string) {
	s = strings.TrimSpace(s)

	i := 0
	for i < len(s) && !unicode.IsSpace(rune(s[i])) {
		i++
	}

	return s[:i], strings.TrimSpace(s[i:])
}

func firstWord(s string) string {
	key, _ := splitKey(s)
	return key
}

func splitList(s string) []string {
	var out []string

	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}

	return out
}

func parsePositive(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, err
	}

	return n, nil
}
