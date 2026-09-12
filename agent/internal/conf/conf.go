/*
 * Конфиг процесса: файл плюс окружение сверху.
 *
 * Назначения архива и адрес шины живут здесь, а не на проводе и не в nginx.
 * Три ноды стенда монтируют один файл; то, чем они отличаются (имя), задаёт
 * WAF_NODE_ID. Реквизиты S3 файл только называет — сами ключи в секрете.
 *
 * Окружение без файла по-прежнему достаточно: так поднимаются тесты и старый
 * compose. Файл указан и не читается — ошибка, тихо уйти в «как раньше» нельзя.
 */

package conf

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/exemt/placitum-node/agent/internal/handoff"
	"github.com/exemt/placitum-node/agent/internal/nginxlog"
	"github.com/exemt/placitum-node/agent/internal/retain"
)

const (
	defaultPath      = "/etc/waf/agent.conf"
	defaultNATS      = "nats://127.0.0.1:4222"
	defaultDataDir   = "/var/lib/waf/agent"
	defaultHeartbeat = 4 * time.Second
	defaultConfDir   = "/etc/nginx"
	defaultStoreDir  = "/var/lib/waf/store"
	defaultNginxBin  = "nginx"
)

type Config struct {
	// Path — какой файл реально прочитали. Пусто: работаем только с окружением.
	Path string

	NodeID      string
	NodeKey     string
	DataDir     string
	Heartbeat   time.Duration
	VerdictSock string

	// LogSock — второй сокет ноды: строки access_log и error_log, которые
	// nginx кладёт туда своим syslog-писателем. Пустая строка выключает
	// приёмник целиком — на ноде, где логи собирает кто-то другой, лишний
	// сокет в /var/run/waf только путает.
	LogSock string

	NATS string

	// RedisURL -- обменник: объекты запроса, которые модуль кладёт по локатору,
	// а архив забирает после вердикта. RedisInternalURL -- внутренний Redis
	// контура: блобы поколения nginx (waf.blob.<sha256>), которые сюда кладёт
	// контроллер. Пусто -- блобы читаются из обменника, как до разделения.
	RedisURL         string
	RedisInternalURL string
	RedisNodes       []string

	ControllerURL string
	Scope         string

	NginxBin  string
	NginxConf string
	ConfDir   string
	StoreDir  string
	// NginxManage -- ведёт ли этот агент конфигурацию nginx. Выключено, когда
	// агент стоит сайдкаром: там нет ни бинаря nginx, ни его дерева, и
	// попытка применить поколение оставляла бы ноду в вечном apply_failed,
	// хотя аудит, архив и пульс на ней работают.
	NginxManage bool

	Retain retain.Config
}

// Load собирает конфиг. Порядок: умолчания → файл → непустое окружение.
// Окружение сверху, чтобы один agent.conf обслуживал три ноды.
func Load() (Config, error) {
	c := Config{
		DataDir:     defaultDataDir,
		Heartbeat:   defaultHeartbeat,
		VerdictSock: handoff.DefaultPath,
		LogSock:     nginxlog.DefaultPath,
		NATS:        defaultNATS,
		NginxBin:    defaultNginxBin,
		ConfDir:     defaultConfDir,
		StoreDir:    defaultStoreDir,
		NginxManage: true,
		Retain: retain.Config{
			Bucket: map[string]string{},
			Batch:  map[string]retain.BatchPolicy{},
		},
	}

	path, required := configPath()
	if path != "" {
		text, err := os.ReadFile(path)
		if err != nil {
			if required || !os.IsNotExist(err) {
				return Config{}, fmt.Errorf("agent config %s: %w", path, err)
			}
		} else {
			if err := parse(&c, string(text), path); err != nil {
				return Config{}, err
			}
			c.Path = path
		}
	}

	if err := c.overlayEnv(); err != nil {
		return Config{}, err
	}

	if err := c.Retain.Finish(); err != nil {
		return Config{}, err
	}

	return c, nil
}

func configPath() (string, bool) {
	if path := strings.TrimSpace(os.Getenv("WAF_AGENT_CONFIG")); path != "" {
		return path, true
	}

	if st, err := os.Stat(defaultPath); err == nil && !st.IsDir() {
		return defaultPath, false
	}

	return "", false
}

func (c *Config) overlayEnv() error {
	set := func(dst *string, key string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}

	set(&c.NodeID, "WAF_NODE_ID")
	set(&c.NodeKey, "WAF_NODE_KEY")
	set(&c.DataDir, "WAF_DATA_DIR")
	set(&c.VerdictSock, "WAF_VERDICT_SOCK")

	/*
	 * Сокет логов выключается пустым значением, поэтому через общий set его
	 * не проведёшь: тот пустое окружение считает «не задано». Здесь пустая
	 * строка — это ответ, а не её отсутствие.
	 */
	if v, ok := os.LookupEnv("WAF_LOG_SOCK"); ok {
		c.LogSock = strings.TrimSpace(v)
	}

	set(&c.NATS, "WAF_NATS_URL")
	set(&c.RedisURL, "WAF_REDIS_URL")
	set(&c.RedisInternalURL, "WAF_REDIS_INTERNAL_URL")
	set(&c.ControllerURL, "WAF_CONTROLLER_URL")
	set(&c.Scope, "WAF_SCOPE")
	set(&c.NginxBin, "WAF_NGINX_BIN")
	set(&c.NginxConf, "WAF_NGINX_CONF")
	set(&c.ConfDir, "WAF_CONF_DIR")
	set(&c.StoreDir, "WAF_STORE_DIR")

	if v := os.Getenv("WAF_NGINX_MANAGE"); v != "" {
		switch v {
		case "1", "on", "true", "yes":
			c.NginxManage = true
		case "0", "off", "false", "no":
			c.NginxManage = false
		default:
			return fmt.Errorf("WAF_NGINX_MANAGE: expected on or off, got %q", v)
		}
	}

	if v := os.Getenv("WAF_HEARTBEAT_EVERY"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("WAF_HEARTBEAT_EVERY: expected a duration, got %q", v)
		}
		c.Heartbeat = d
	}

	if v := os.Getenv("WAF_RETAIN_REDIS_URL"); v != "" {
		if err := c.Retain.SetRedis(v); err != nil {
			return err
		}
	} else if c.RedisURL != "" && c.Retain.Redis.Addr == "" {
		if err := c.Retain.SetRedis(c.RedisURL); err != nil {
			return err
		}
	}

	if v := os.Getenv("WAF_RETAIN_REDIS_NODES"); v != "" {
		c.Retain.Redis.Nodes = splitList(v)
	} else if len(c.RedisNodes) != 0 && len(c.Retain.Redis.Nodes) == 0 {
		c.Retain.Redis.Nodes = append([]string(nil), c.RedisNodes...)
	}

	set(&c.Retain.S3.Endpoint, "WAF_RETAIN_S3_ENDPOINT")
	set(&c.Retain.S3.Region, "WAF_RETAIN_S3_REGION")
	set(&c.Retain.S3.Credentials, "WAF_RETAIN_S3_CREDENTIALS_FILE")
	setBucket(&c.Retain, "headers", "WAF_RETAIN_BUCKET_HEADERS")
	setBucket(&c.Retain, "args", "WAF_RETAIN_BUCKET_ARGS")
	setBucket(&c.Retain, "body", "WAF_RETAIN_BUCKET_BODY")

	if err := overlayNumber(&c.Retain.Workers, "WAF_RETAIN_WORKERS"); err != nil {
		return err
	}
	if err := overlayNumber(&c.Retain.Queue, "WAF_RETAIN_QUEUE"); err != nil {
		return err
	}
	if err := overlayDuration(&c.Retain.OpTimeout, "WAF_RETAIN_OP_TIMEOUT"); err != nil {
		return err
	}

	return overlayBatch(&c.Retain)
}

func setBucket(cfg *retain.Config, kind, key string) {
	if v := os.Getenv(key); v != "" {
		if cfg.Bucket == nil {
			cfg.Bucket = map[string]string{}
		}
		cfg.Bucket[kind] = v
	}
}

func overlayBatch(cfg *retain.Config) error {
	if cfg.Batch == nil {
		cfg.Batch = map[string]retain.BatchPolicy{}
	}

	for _, kind := range []string{"headers", "args", "body"} {
		key := "WAF_RETAIN_BATCH_" + strings.ToUpper(kind)
		v := os.Getenv(key)
		if v == "" {
			continue
		}

		policy, err := retain.ParseBatch(v)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}

		cfg.Batch[kind] = policy
	}

	return nil
}

func overlayNumber(dst *int, key string) error {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}

	n, err := parsePositive(v)
	if err != nil {
		return fmt.Errorf("%s: expected a positive number, got %q", key, v)
	}

	*dst = n
	return nil
}

func overlayDuration(dst *time.Duration, key string) error {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}

	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fmt.Errorf("%s: expected a duration, got %q", key, v)
	}

	*dst = d
	return nil
}
