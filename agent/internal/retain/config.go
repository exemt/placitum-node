/*
 * Настройка архивации: окружение, как и всё остальное у агента.
 *
 * Назначения и реквизиты живут здесь, а не на проводе. Модуль про архив знает
 * ровно одно число — срок хранения в секундах; куда именно и под какими ключами
 * ляжет объект, решает агент. Поэтому смена бакета или региона не трогает ни
 * одну конфигурацию nginx.
 */

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

	// Bucket — назначение по виду объекта. Виды разведены по бакетам не из
	// аккуратности: у тела, заголовков и строки запроса разная
	// чувствительность, а значит разные политики доступа, разные сроки и
	// разный ответ на регуляторное «удалите все тела».
	//
	// Пусто для вида — архивация этого вида у агента выключена, объект уедет
	// в записи как archive_error.
	Bucket map[string]string

	Workers   int
	Queue     int
	OpTimeout time.Duration

	// Batch — как копить PUT по виду. Пусто или off: сразу, один объект —
	// один запрос. S3 не умеет пакетную запись, поэтому корзина только
	// выбирает момент вспышки: по наполнению, по таймауту, или по обоим.
	// Секции друг друга не ждут.
	Batch map[string]BatchPolicy
}

// BatchPolicy — пороги одной корзины. Size <= 1 и Timeout == 0 — сразу.
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

	// Nodes — узлы, на которые агенту позволено ходить по подсказке локатора.
	// Подсказка приходит с датаграммой, а сокет вердиктов доступен всем на
	// ноде: без списка это был бы способ заставить агента постучаться по
	// произвольному адресу с реквизитами обменника в руках.
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

// FromEnv собирает настройку. Ничего не задано — архивация выключена, и это
// не ошибка: модуль может её и не просить. Задано криво — ошибка на старте,
// потому что тихо деградировать в «архива нет» значит однажды обнаружить
// пустой бакет вместо доказательной базы.
func FromEnv() (Config, error) {
	cfg := Config{
		Bucket: map[string]string{
			"headers": os.Getenv("WAF_RETAIN_BUCKET_HEADERS"),
			"args":    os.Getenv("WAF_RETAIN_BUCKET_ARGS"),
			"body":    os.Getenv("WAF_RETAIN_BUCKET_BODY"),
		},
		S3: S3Config{
			Endpoint:    os.Getenv("WAF_RETAIN_S3_ENDPOINT"),
			Region:      os.Getenv("WAF_RETAIN_S3_REGION"),
			Credentials: os.Getenv("WAF_RETAIN_S3_CREDENTIALS_FILE"),
		},
		Batch: map[string]BatchPolicy{},
	}

	if err := cfg.SetRedis(os.Getenv("WAF_RETAIN_REDIS_URL")); err != nil {
		return Config{}, err
	}

	for _, node := range strings.Split(os.Getenv("WAF_RETAIN_REDIS_NODES"), ",") {
		if node = strings.TrimSpace(node); node != "" {
			cfg.Redis.Nodes = append(cfg.Redis.Nodes, node)
		}
	}

	var err error

	if cfg.Workers, err = number("WAF_RETAIN_WORKERS", defaultWorkers); err != nil {
		return Config{}, err
	}

	if cfg.Queue, err = number("WAF_RETAIN_QUEUE", defaultQueue); err != nil {
		return Config{}, err
	}

	if cfg.OpTimeout, err = span("WAF_RETAIN_OP_TIMEOUT",
		defaultOpTimeout); err != nil {
		return Config{}, err
	}

	if err := cfg.readBatchEnv(); err != nil {
		return Config{}, err
	}

	return cfg, cfg.Finish()
}

// Finish дочитывает секрет и проверяет, что архив либо выключен, либо собран.
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

// SetRedis разбирает URL обменника. Пустая строка — не ошибка: архив могут
// не просить, и тогда адрес подставится нормализацией.
func (c *Config) SetRedis(value string) error {
	return c.readRedis(value)
}

// Enabled — есть ли куда складывать. Само по себе наличие эндпоинта не считается:
// без реквизитов и хотя бы одного бакета архивация не состоится.
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

// node выбирает узел обменника. Подсказка локатора — единственный способ узнать,
// куда лёг ключ, но доверять ей можно только в пределах известных адресов.
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

// readCredentials читает реквизиты из файла, а не из окружения: окружение
// процесса видно соседям по машине и уезжает в дампы, а у файла есть режим и
// владелец. Формат — те же ключи, что у ~/.aws/credentials, без секций.
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

func number(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: expected a positive number, got %q", key, value)
	}

	return n, nil
}

func span(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: expected a duration, got %q", key, value)
	}

	return d, nil
}

func (c *Config) readBatchEnv() error {
	if c.Batch == nil {
		c.Batch = map[string]BatchPolicy{}
	}

	for _, kind := range []string{"headers", "args", "body"} {
		key := "WAF_RETAIN_BATCH_" + strings.ToUpper(kind)
		value := os.Getenv(key)
		if value == "" {
			continue
		}

		policy, err := ParseBatch(value)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}

		c.Batch[kind] = policy
	}

	return nil
}

// KnownKind — вид объекта обменника, который агент умеет класть в архив.
func KnownKind(kind string) bool {
	switch kind {
	case "headers", "args", "body":
		return true
	}

	return false
}

// ParseBatch разбирает «off» или «size=N timeout=D». Запятая и пробел —
// одно и то же: в файле удобнее пробел, в окружении — запятая.
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
