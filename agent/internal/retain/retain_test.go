package retain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exemt/placitum-node/agent/internal/audit"
)

// Датаграмма с двумя удерживаемыми объектами: заголовки и тело оставлены
// агенту, строки запроса нет.
const retained = `{"ray":"3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442",` +
	`"node":"nginx-1","phase":"request","ts":"2026-08-15T21:44:12.907Z",` +
	`"http":{"method":"POST","status":403},"verdict":"deny",` +
	`"store":{"headers":{"size":3,"store":"hot","driver":"redis",` +
	`"key":"nginx-1:48:req:hdr","expires_at":1723753500},` +
	`"args":null,"body":{"size":4,"sha256":"9f86","store":"hot",` +
	`"driver":"redis","key":"nginx-1:48:req","expires_at":1723753500},` +
	`"archive":{"headers":{"ttl":2592000},"body":{"ttl":15552000}}},` +
	`"waf_latency_us":8100}`

const plain = `{"ray":"r","node":"n","verdict":"allow",` +
	`"store":{"headers":null,"args":null,"body":null}}`

// Так момент удаления называет само хранилище: lifecycle-правило бакета в
// ответе на PUT. Маршрут называет срок, хранилище — дату, и в записи нужна
// вторая: по ней читатель решает, идти ли за объектом.
const archiveExpiry = "Wed, 21 Oct 2026 00:00:00 GMT"

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func decode(t *testing.T, raw string) audit.Decision {
	t.Helper()

	d, err := audit.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func locators(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()

	var doc struct {
		Store map[string]json.RawMessage `json:"store"`
	}

	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("published record is not JSON: %s", raw)
	}

	out := map[string]map[string]any{}

	for _, kind := range audit.Kinds {
		var fields map[string]any

		if err := json.Unmarshal(doc.Store[kind], &fields); err != nil {
			continue
		}

		out[kind] = fields
	}

	return out
}

// Запись без archive агент не трогает вовсе: ни разбора, ни очереди.
func TestHandlePassesThrough(t *testing.T) {
	var got []byte

	pool := New(Config{}, func(d audit.Decision) error {
		got = d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, plain))

	if string(got) != plain {
		t.Fatalf("record changed: %s", got)
	}
}

// Превью без archive: срез уже в записи. Агент обменник не читает и запись
// не трогает. Нет archive на маршруте — preview не берётся из чужого объекта.
func TestHandlePreviewWithoutArchive(t *testing.T) {
	const preview = `{"ray":"r","node":"n","phase":"request","verdict":"allow",` +
		`"store":{"headers":null,"args":null,"body":null},` +
		`"headers_preview":{"raw":"host: a"}}`

	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("must-not-read"),
	})
	defer store.close()

	var got []byte

	pool := New(Config{Redis: RedisConfig{Addr: store.addr()}},
		func(d audit.Decision) error {
			got = d.Raw
			return nil
		}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, preview))

	if string(got) != preview {
		t.Fatalf("record changed: %s", got)
	}

	if steps := store.steps(); len(steps) != 0 {
		t.Fatalf("store was touched: %v", steps)
	}
}

// when=deny на allow: модуль не кладёт store.archive. Агент обменник не трогает.
func TestHandleWhenDenyOnAllow(t *testing.T) {
	const allow = `{"ray":"r","node":"n","phase":"request","verdict":"allow",` +
		`"store":{"headers":{"store":"hot","driver":"redis",` +
		`"key":"nginx-1:48:req:hdr","expires_at":1723753500},` +
		`"args":null,"body":null}}`

	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
	})
	defer store.close()

	var got []byte

	pool := New(Config{Redis: RedisConfig{Addr: store.addr()}},
		func(d audit.Decision) error {
			got = d.Raw
			return nil
		}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, allow))

	if string(got) != allow {
		t.Fatalf("record changed: %s", got)
	}

	if steps := store.steps(); len(steps) != 0 {
		t.Fatalf("store was touched: %v", steps)
	}
}

// Reload кладёт в обменник оригинал (ключ с фазой). Агент везёт байты как есть,
// не режет «как инспекторам» и не переписывает ключ.
func TestArchiveKeepsReloadOriginal(t *testing.T) {
	original := []byte("cookie=secret; session=wider-than-capture")
	const datagram = `{"ray":"r1","node":"nginx-1","phase":"request",` +
		`"ts":"2026-08-15T21:44:12.907Z","http":{"status":403},"verdict":"deny",` +
		`"store":{"headers":{"size":40,"store":"hot","driver":"redis",` +
		`"key":"nginx-1:48:req:hdr","expires_at":1723753500},` +
		`"args":null,"body":null,` +
		`"archive":{"headers":{"ttl":3600}}}}`

	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": original,
	})
	defer store.close()

	var (
		mu   sync.Mutex
		body string
	)

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			body = string(raw)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis: RedisConfig{Addr: store.addr()},
		S3: S3Config{
			Endpoint: archive.URL,
			Region:   "ru-1",
			Access:   "key",
			Secret:   "secret",
		},
		Bucket:  map[string]string{"headers": "waf-headers"},
		Workers: 1,
		Queue:   4,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())
	defer pool.Close()

	pool.Handle(decode(t, datagram))

	select {
	case <-published:
	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}

	mu.Lock()
	defer mu.Unlock()

	if body != string(original) {
		t.Fatalf("agent recut the object: %q", body)
	}
}

// Архивация у агента не настроена, а модуль объект удержал. Соврать в записи,
// что объект где-то лежит, нельзя: его вот-вот срежет retain_ttl.
//
// Ключ при этом не дожидается срока: запись уже сказала, что объекта не будет,
// и приходить за ним некому. Тот же путь — у переполненной очереди переноса,
// где под нагрузкой и набирается обменник на все пять минут retain_ttl.
func TestHandleDegradesWhenArchiveIsOff(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	var got []byte

	pool := New(Config{Redis: RedisConfig{Addr: store.addr()}},
		func(d audit.Decision) error {
			store.mark("publish")
			got = d.Raw
			return nil
		}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, retained))

	locs := locators(t, got)

	for _, kind := range []string{"headers", "body"} {
		if locs[kind]["unavailable"] != reasonError {
			t.Fatalf("%s: %v", kind, locs[kind])
		}

		if _, ok := locs[kind]["key"]; ok {
			t.Fatalf("%s keeps a dead address: %v", kind, locs[kind])
		}
	}

	// Описание остаётся: оно верно и без полезной нагрузки.
	if locs["body"]["sha256"] != "9f86" {
		t.Fatalf("description lost: %v", locs["body"])
	}

	store.wait(t, 3)

	steps := store.steps()
	if len(steps) != 3 || steps[0] != "publish" {
		t.Fatalf("cleanup did not follow publish: %v", steps)
	}

	deleted := map[string]bool{steps[1]: true, steps[2]: true}
	for _, key := range []string{"nginx-1:48:req:hdr", "nginx-1:48:req"} {
		if !deleted["del "+key] {
			t.Fatalf("%s outlived the record: %v", key, steps)
		}
	}
}

func TestArchiveMovesObjects(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	type object struct {
		body string
		tag  string
	}

	var (
		mu      sync.Mutex
		objects = map[string]object{}
	)

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)

			mu.Lock()
			objects[r.URL.Path] = object{
				body: string(body),
				tag:  r.Header.Get("X-Amz-Tagging"),
			}
			mu.Unlock()

			if auth := r.Header.Get("Authorization"); auth == "" {
				t.Errorf("unsigned request: %s", r.URL.Path)
			}

			w.Header().Set("X-Amz-Expiration",
				`expiry-date="`+archiveExpiry+`", rule-id="waf-retain-180d"`)
			w.WriteHeader(http.StatusOK)
		}))

	defer archive.Close()

	published := make(chan []byte, 1)

	cfg := Config{
		Redis: RedisConfig{Addr: store.addr()},
		S3: S3Config{
			Endpoint: archive.URL,
			Region:   "ru-1",
			Access:   "key",
			Secret:   "secret",
		},
		Bucket: map[string]string{
			"headers": "waf-headers",
			"body":    "waf-bodies",
		},
		Workers: 1,
		Queue:   4,
	}

	pool := New(cfg, func(d audit.Decision) error {
		store.mark("publish")
		published <- d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, retained))

	var raw []byte

	select {
	case raw = <-published:
	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}

	locs := locators(t, raw)

	want := map[string]string{
		"headers": "2026/08/15/nginx-1/3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442.hdr",
		"body":    "2026/08/15/nginx-1/3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442.body",
	}

	due, err := http.ParseTime(archiveExpiry)
	if err != nil {
		t.Fatal(err)
	}

	for kind, key := range want {
		if locs[kind]["store"] != "archive" || locs[kind]["driver"] != "s3" {
			t.Fatalf("%s: %v", kind, locs[kind])
		}

		if locs[kind]["key"] != key {
			t.Fatalf("%s key: %v", kind, locs[kind]["key"])
		}

		// Срок из ответа архива, а не обменника: по нему читатель записи
		// решает, идти ли за объектом вообще.
		if locs[kind]["expires_at"] != float64(due.Unix()) {
			t.Fatalf("%s expiry: %v", kind, locs[kind]["expires_at"])
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if got := objects["/waf-headers/"+want["headers"]]; got.body != "hdr" {
		t.Fatalf("headers object: %+v", got)
	}

	if got := objects["/waf-bodies/"+want["body"]]; got.body != "body" ||
		got.tag != "waf-retain-ttl=15552000" {
		t.Fatalf("body object: %+v", got)
	}

	// DEL строго после публикации. Падение между ними оставляет осиротевший
	// ключ, который доберёт TTL; в обратном порядке теряется запись, а объект
	// остаётся в архиве без единой ссылки на себя.
	store.wait(t, 2)

	steps := store.steps()
	if len(steps) == 0 || steps[0] != "publish" {
		t.Fatalf("store was cleaned before publish: %v", steps)
	}
}

// Ключа не стало, пока запись стояла в очереди. Это не отказ архива, и путать
// одно с другим при разборе инцидента дорого.
func TestArchiveMarksExpired(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{})
	defer store.close()

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("nothing to put")
		}))

	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"headers": "b", "body": "b"},
		Workers: 1,
		Queue:   4,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, retained))

	select {
	case raw := <-published:
		locs := locators(t, raw)

		if locs["body"]["unavailable"] != reasonExpired {
			t.Fatalf("body: %v", locs["body"])
		}

	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}
}

// Бакета для вида нет — этот вид уезжает archive_error, остальные едут своим
// ходом. Ошибка на одном объекте не касается других.
func TestArchiveSkipsKindWithoutBucket(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"body": "waf-bodies"},
		Workers: 1,
		Queue:   4,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, retained))

	select {
	case raw := <-published:
		locs := locators(t, raw)

		if locs["headers"]["unavailable"] != reasonError {
			t.Fatalf("headers: %v", locs["headers"])
		}

		if locs["body"]["store"] != "archive" {
			t.Fatalf("body: %v", locs["body"])
		}

	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}
}

// Предел записи режет агент, а не модуль: в обменнике объект лежит целиком, потому
// что его мог попросить инспектор. В архив уезжает префикс, и локатор обязан
// это объявить — размер и контрольная сумма в нём остались от целого объекта.
func TestArchiveTrimsByLimit(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	var (
		mu      sync.Mutex
		objects = map[string]string{}
	)

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)

			mu.Lock()
			objects[r.URL.Path] = string(body)
			mu.Unlock()

			w.WriteHeader(http.StatusOK)
		}))

	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"headers": "b", "body": "b"},
		Workers: 1,
		Queue:   4,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	limited := strings.Replace(retained,
		`"body":{"ttl":15552000}`, `"body":{"ttl":15552000,"limit":2}`, 1)

	pool.Handle(decode(t, limited))

	select {
	case raw := <-published:
		locs := locators(t, raw)

		if locs["body"]["truncated"] != true ||
			locs["body"]["complete"] != false {
			t.Fatalf("trim not marked: %v", locs["body"])
		}

		// Предел назначен телу: строка директивы настраивает только названные
		// в ней объекты, и на заголовки он перетечь не смеет.
		if locs["headers"]["truncated"] == true {
			t.Fatalf("headers trimmed: %v", locs["headers"])
		}

	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}

	mu.Lock()
	defer mu.Unlock()

	name := "/b/2026/08/15/nginx-1/3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442."

	if objects[name+"body"] != "bo" {
		t.Fatalf("body object: %q", objects[name+"body"])
	}

	if objects[name+"hdr"] != "hdr" {
		t.Fatalf("headers object: %q", objects[name+"hdr"])
	}
}

// Объект требовался и оказался пуст. Пустышка в бакете стоит места в листинге и
// ничего не отвечает тому, кто за ней придёт, поэтому в архив она не едет; но
// объект просили, и запись обязана сказать, чем это кончилось.
func TestArchiveMarksEmpty(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     {},
	})
	defer store.close()

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".body") {
				t.Errorf("empty object was put: %s", r.URL.Path)
			}

			w.WriteHeader(http.StatusOK)
		}))

	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"headers": "b", "body": "b"},
		Workers: 1,
		Queue:   4,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	defer pool.Close()

	pool.Handle(decode(t, retained))

	select {
	case raw := <-published:
		locs := locators(t, raw)

		if locs["body"]["unavailable"] != reasonEmpty {
			t.Fatalf("body: %v", locs["body"])
		}

		if locs["headers"]["store"] != "archive" {
			t.Fatalf("headers: %v", locs["headers"])
		}

	case <-time.After(5 * time.Second):
		t.Fatal("record was never published")
	}
}

// Очередь переполнена — это обратное давление, а не отказ хранилища: лечатся
// они разным, и по записи это должно различаться.
func TestArchiveMarksOverload(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	// Единственный воркер застревает на PUT, и очередь глубиной в одну запись
	// набивается со второй же датаграммы.
	gate := make(chan struct{})

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			<-gate
			w.WriteHeader(http.StatusOK)
		}))

	defer archive.Close()

	published := make(chan []byte, 16)

	pool := New(Config{
		Redis:     RedisConfig{Addr: store.addr()},
		S3:        S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:    map[string]string{"headers": "b", "body": "b"},
		Workers:   1,
		Queue:     1,
		OpTimeout: 30 * time.Second,
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	seen := false

	for i := 0; i < 4 && !seen; i++ {
		pool.Handle(decode(t, retained))

		select {
		case raw := <-published:
			if locators(t, raw)["body"]["unavailable"] == reasonOverload {
				seen = true
			}
		default:
		}
	}

	close(gate)
	pool.Close()

	if !seen {
		t.Fatal("a full queue must say so in the record")
	}
}

func TestObjectName(t *testing.T) {
	d := audit.Decision{
		Ray:  "3f9c1e77",
		Node: "nginx-1",
		TS:   "2026-08-15T23:44:12.907Z",
	}

	got := objectName(d, "body")
	want := "2026/08/15/nginx-1/3f9c1e77.body"

	if got != want {
		t.Fatalf("objectName = %q, want %q", got, want)
	}

	// Час записи взят из события, а не из момента переноса: иначе запросы
	// последней минуты суток оказались бы в завтрашней папке.
	d.TS = "2026-08-15T23:59:59.999+03:00"

	if got := objectName(d, "headers"); got !=
		"2026/08/15/nginx-1/3f9c1e77.hdr" {
		t.Fatalf("timezone ignored: %q", got)
	}
}

// Ноль — «хранить вечно», и тега тогда нет вовсе: "waf-retain-ttl=0" совпал бы
// с неаккуратно написанным lifecycle-правилом и удалил бы то, что просили
// хранить всегда.
func TestRetainTag(t *testing.T) {
	if got := retainTag(15552000); got != "waf-retain-ttl=15552000" {
		t.Fatalf("retainTag = %q", got)
	}

	if got := retainTag(0); got != "" {
		t.Fatalf("forever must not be tagged: %q", got)
	}
}

// Срок называет хранилище, и разбирать его приходится из строки. Незнакомая
// форма — ноль, а не догадка: соврать о сроке хуже, чем его не знать.
func TestExpiryOf(t *testing.T) {
	due, err := http.ParseTime(archiveExpiry)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		header string
		want   int64
	}{
		{`expiry-date="` + archiveExpiry + `", rule-id="waf-30d"`, due.Unix()},

		// Порядок полей — дело хранилища, а не наше.
		{`rule-id="waf-30d", expiry-date="` + archiveExpiry + `"`, due.Unix()},

		// Правила удаления в бакете нет — заголовка тоже.
		{"", 0},

		// Форма чужая: закрывающей кавычки нет, дата не разбирается, речь
		// вообще не об удалении.
		{`expiry-date="` + archiveExpiry, 0},
		{`expiry-date="через месяц"`, 0},
		{`transition-date="` + archiveExpiry + `"`, 0},
	}

	for _, item := range cases {
		if got := expiryOf(item.header); got != item.want {
			t.Fatalf("expiryOf(%q) = %d, want %d",
				item.header, got, item.want)
		}
	}
}

// Подсказка приходит с датаграммой, а сокет вердиктов доступен всем на ноде.
// Ходить по ней куда угодно с реквизитами обменника в руках агент не должен.
func TestNodeAllowList(t *testing.T) {
	cfg := Config{Redis: RedisConfig{
		Addr:  "10.0.0.1:6379",
		Nodes: []string{"10.0.0.2:6379"},
	}}

	cases := map[string]string{
		"":                "10.0.0.1:6379",
		"10.0.0.1:6379":   "10.0.0.1:6379",
		"10.0.0.2:6379":   "10.0.0.2:6379",
		"evil.example:80": "10.0.0.1:6379",
	}

	for hint, want := range cases {
		if got := cfg.node(hint); got != want {
			t.Fatalf("node(%q) = %q, want %q", hint, got, want)
		}
	}
}

func TestParseBatch(t *testing.T) {
	off, err := ParseBatch("off")
	if err != nil || !off.immediate() {
		t.Fatalf("off: %+v %v", off, err)
	}

	p, err := ParseBatch("size=32 timeout=50ms")
	if err != nil || p.Size != 32 || p.Timeout != 50*time.Millisecond {
		t.Fatalf("pair: %+v %v", p, err)
	}

	p, err = ParseBatch("size=8,timeout=100ms")
	if err != nil || p.Size != 8 || p.Timeout != 100*time.Millisecond {
		t.Fatalf("comma: %+v %v", p, err)
	}

	if _, err := ParseBatch("count=8"); err == nil {
		t.Fatal("unknown option accepted")
	}
}

// Корзина копит до размера и не публикует запись раньше времени: одна секция
// не наполнена — локаторы ещё не архивные.
func TestBatchFlushesOnSize(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
		"nginx-1:49:req:hdr": []byte("HDR"),
		"nginx-1:49:req":     []byte("BODY"),
	})
	defer store.close()

	puts := make(chan string, 8)
	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			puts <- r.URL.Path
			w.WriteHeader(http.StatusOK)
		}))
	defer archive.Close()

	published := make(chan []byte, 4)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"headers": "b", "body": "b"},
		Workers: 1,
		Queue:   4,
		Batch: map[string]BatchPolicy{
			"headers": {Size: 2},
			"body":    {Size: 2},
		},
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())
	defer pool.Close()

	pool.Handle(decode(t, retained))

	select {
	case <-published:
		t.Fatal("published before the basket filled")
	case <-time.After(50 * time.Millisecond):
	}

	next := strings.ReplaceAll(retained,
		"3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442",
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	next = strings.ReplaceAll(next, "nginx-1:48:", "nginx-1:49:")
	pool.Handle(decode(t, next))

	for i := 0; i < 2; i++ {
		select {
		case <-published:
		case <-time.After(5 * time.Second):
			t.Fatal("records were never published")
		}
	}

	if len(puts) < 4 {
		t.Fatalf("puts: %d", len(puts))
	}
}

// Таймаут вспыхивает корзину, даже если размер не набран. Иначе последний
// запрос суток ждал бы следующего.
func TestBatchFlushesOnTimeout(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:   RedisConfig{Addr: store.addr()},
		S3:      S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:  map[string]string{"headers": "b", "body": "b"},
		Workers: 1,
		Queue:   4,
		Batch: map[string]BatchPolicy{
			"headers": {Size: 64, Timeout: 40 * time.Millisecond},
			"body":    {Size: 64, Timeout: 40 * time.Millisecond},
		},
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())
	defer pool.Close()

	pool.Handle(decode(t, retained))

	select {
	case raw := <-published:
		if locators(t, raw)["body"]["store"] != "archive" {
			t.Fatalf("body: %v", locators(t, raw)["body"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout did not flush")
	}
}

// Секции не ждут друг друга: заголовки уезжают сразу, тело копится. Запись
// при этом не публикуется, пока тело не вспыхнет — локатор не должен врать.
func TestBatchSectionsIndependent(t *testing.T) {
	store := newFakeStore(t, map[string][]byte{
		"nginx-1:48:req:hdr": []byte("hdr"),
		"nginx-1:48:req":     []byte("body"),
	})
	defer store.close()

	var (
		mu   sync.Mutex
		puts []string
	)
	gate := make(chan struct{})

	archive := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			puts = append(puts, r.URL.Path)
			mu.Unlock()
			if strings.HasSuffix(r.URL.Path, ".body") {
				<-gate
			}
			w.WriteHeader(http.StatusOK)
		}))
	defer archive.Close()

	published := make(chan []byte, 1)

	pool := New(Config{
		Redis:     RedisConfig{Addr: store.addr()},
		S3:        S3Config{Endpoint: archive.URL, Access: "k", Secret: "s"},
		Bucket:    map[string]string{"headers": "b", "body": "b"},
		Workers:   1,
		Queue:     4,
		OpTimeout: 30 * time.Second,
		Batch: map[string]BatchPolicy{
			"headers": {},
			"body":    {Size: 8, Timeout: time.Hour},
		},
	}, func(d audit.Decision) error {
		published <- d.Raw
		return nil
	}, quiet())

	pool.Handle(decode(t, retained))

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(puts)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("headers were not put independently")
		case <-time.After(10 * time.Millisecond):
		}
	}

	select {
	case <-published:
		t.Fatal("published while body was still sitting in the basket")
	case <-time.After(40 * time.Millisecond):
	}

	close(gate)
	pool.Close()

	select {
	case raw := <-published:
		locs := locators(t, raw)
		if locs["headers"]["store"] != "archive" {
			t.Fatalf("headers: %v", locs["headers"])
		}
		if locs["body"]["store"] != "archive" {
			t.Fatalf("body: %v", locs["body"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not flush the leftover body")
	}
}

func TestConfigRequiresWholeSetup(t *testing.T) {
	cfg := Config{S3: S3Config{Endpoint: "https://s3.example.com"}}
	cfg.normalize()

	if cfg.Enabled() {
		t.Fatal("endpoint alone is not enough")
	}

	cfg.S3.Access, cfg.S3.Secret = "k", "s"

	if cfg.Enabled() {
		t.Fatal("credentials alone are not enough")
	}

	cfg.Bucket["body"] = "waf-bodies"

	if !cfg.Enabled() {
		t.Fatalf("still disabled: %s", cfg.missing())
	}
}

// --- обменник на TCP -----------------------------------------------------------

// fakeStore — RESP ровно в объёме двух команд, которые агент умеет посылать.
// Заодно журнал шагов: порядок публикации и уборки — часть контракта.
type fakeStore struct {
	ln   net.Listener
	data map[string][]byte

	mu    sync.Mutex
	trace []string
	done  chan struct{}
}

func newFakeStore(t *testing.T, data map[string][]byte) *fakeStore {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &fakeStore{ln: ln, data: data, done: make(chan struct{}, 16)}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go s.serve(conn)
		}
	}()

	return s
}

func (s *fakeStore) addr() string { return s.ln.Addr().String() }

func (s *fakeStore) close() { _ = s.ln.Close() }

func (s *fakeStore) mark(step string) {
	s.mu.Lock()
	s.trace = append(s.trace, step)
	s.mu.Unlock()

	select {
	case s.done <- struct{}{}:
	default:
	}
}

func (s *fakeStore) steps() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.trace...)
}

func (s *fakeStore) wait(t *testing.T, steps int) {
	t.Helper()

	for i := 0; i < steps; i++ {
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d steps happened: %v", i, s.steps())
		}
	}
}

func (s *fakeStore) serve(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)

	for {
		args, err := readCommand(br)
		if err != nil {
			return
		}

		switch args[0] {

		case "GET":
			value, ok := s.data[args[1]]
			if !ok {
				fmt.Fprint(conn, "$-1\r\n")
				continue
			}

			fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(value), value)

		case "DEL":
			s.mark("del " + args[1])
			delete(s.data, args[1])
			fmt.Fprint(conn, ":1\r\n")

		default:
			fmt.Fprint(conn, "+OK\r\n")
		}
	}
}

func readCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("not an array: %q", line)
	}

	count, err := strconv.Atoi(trimCRLF(line[1:]))
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, count)

	for i := 0; i < count; i++ {
		head, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}

		size, err := strconv.Atoi(trimCRLF(head[1:]))
		if err != nil {
			return nil, err
		}

		buf := make([]byte, size+2)

		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}

		args = append(args, string(buf[:size]))
	}

	return args, nil
}

func trimCRLF(s string) string {
	for len(s) != 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}

	return s
}

// Имя объекта: у фазы ответа свой сегмент, у запроса -- нет. Общий ray
// двух фаз без этого клал бы тело ответа поверх тела запроса.
func TestObjectNameCarriesPhase(t *testing.T) {
	req := audit.Decision{TS: "2026-08-15T21:44:12.907Z", Node: "nginx-1", Ray: "r1", Phase: "request"}
	rsp := audit.Decision{TS: "2026-08-15T21:44:12.907Z", Node: "nginx-1", Ray: "r1", Phase: "response"}

	if got := objectName(req, "body"); got != "2026/08/15/nginx-1/r1.body" {
		t.Fatalf("request: %q", got)
	}
	if got := objectName(rsp, "body"); got != "2026/08/15/nginx-1/r1.response.body" {
		t.Fatalf("response: %q", got)
	}
	if got := objectName(rsp, "headers"); got != "2026/08/15/nginx-1/r1.response.hdr" {
		t.Fatalf("response headers: %q", got)
	}
}

// Имя объекта кадра: под ray рукопожатия лежит всё соединение, и кадры
// различаются стороной и номером -- тем же адресом, что у записи в журнале.
// Без него второй кадр лёг бы в архив поверх первого.
func TestObjectNameCarriesFrameAddress(t *testing.T) {
	c2s := audit.Decision{TS: "2026-08-15T21:44:12.907Z", Node: "nginx-1", Ray: "r1",
		Phase: "frame", FrameDirection: "c2s", FrameSeq: 7}
	s2c := audit.Decision{TS: "2026-08-15T21:44:12.907Z", Node: "nginx-1", Ray: "r1",
		Phase: "frame", FrameDirection: "s2c", FrameSeq: 7}

	if got := objectName(c2s, "body"); got != "2026/08/15/nginx-1/r1.frame.c2s.7.body" {
		t.Fatalf("c2s: %q", got)
	}
	if got := objectName(s2c, "body"); got != "2026/08/15/nginx-1/r1.frame.s2c.7.body" {
		t.Fatalf("s2c: %q", got)
	}
}

// Адрес кадра читается из секции frame датаграммы.
func TestDecodeReadsFrameAddress(t *testing.T) {
	d, err := audit.Decode([]byte(`{"ray":"r1","node":"n","phase":"frame",` +
		`"frame":{"conn_id":"r1","seq":3,"direction":"s2c","opcode":"text"},` +
		`"store":{"body":{"key":"n:1:frm"},"archive":{"body":{"ttl":60}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.FrameDirection != "s2c" || d.FrameSeq != 3 {
		t.Fatalf("frame address: %q %d", d.FrameDirection, d.FrameSeq)
	}
	if got := objectName(d, "body"); got == "" || got[len(got)-len("r1.frame.s2c.3.body"):] != "r1.frame.s2c.3.body" {
		t.Fatalf("objectName: %q", got)
	}
}
