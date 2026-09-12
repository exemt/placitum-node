package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// Датаграмма с непустым обменником: два объекта живых, строки запроса нет,
// заголовки и тело оставлены агенту.
const retainDatagram = `{"ray":"3f9c1e77-2a48-4b16-9d0c-5e7a10c8b442",` +
	`"node":"nginx-1","phase":"request","ts":"2026-08-15T21:44:12.907Z",` +
	`"http":{"method":"POST","status":403},"verdict":"deny","code":"inspector",` +
	`"store":{"headers":{"size":96,"store":"hot","driver":"redis",` +
	`"key":"nginx-1:48:req:hdr","expires_at":1723753500,"hint":"10.0.2.11:6379"},` +
	`"args":null,"body":{"size":4096,"sha256":"9f86d081","complete":true,` +
	`"truncated":false,"encoding":"identity","store":"hot","driver":"redis",` +
	`"key":"nginx-1:48:req","expires_at":1723753500,"hint":"10.0.2.11:6379"},` +
	`"archive":{"headers":{"ttl":2592000},"body":{"ttl":0,"limit":8192}}}` +
	`,"waf_latency_us":8100}`

func TestDecodeReadsArchive(t *testing.T) {
	d, err := Decode([]byte(retainDatagram))
	if err != nil {
		t.Fatal(err)
	}

	// Ноль — «хранить вечно», и это не то же, что отсутствие вида в карте:
	// первое означает, что объект удерживается, второе — что нет.
	if d.Archive["headers"].TTL != 2592000 {
		t.Fatalf("archive: %v", d.Archive)
	}

	if terms, ok := d.Archive["body"]; !ok || terms.TTL != 0 {
		t.Fatalf("forever must survive decoding: %v", d.Archive)
	}

	// Предел свой у каждого вида: телу он назначен, заголовкам нет, и
	// назначение одному не смеет протечь на другого.
	if d.Archive["body"].Limit != 8192 || d.Archive["headers"].Limit != 0 {
		t.Fatalf("limit is per kind: %v", d.Archive)
	}

	if _, ok := d.Archive["args"]; ok {
		t.Fatalf("args is not retained: %v", d.Archive)
	}

	if d.TS != "2026-08-15T21:44:12.907Z" {
		t.Fatalf("ts: %q", d.TS)
	}
}

// Быстрый путь обязан оставаться быстрым и, главное, немым: записи без archive
// агент не касается.
func TestDecodeWithoutArchive(t *testing.T) {
	d, err := Decode([]byte(moduleDatagram))
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Archive) != 0 {
		t.Fatalf("archive must be empty: %v", d.Archive)
	}
}

func TestParseStoreLocates(t *testing.T) {
	section, err := ParseStore([]byte(retainDatagram))
	if err != nil {
		t.Fatal(err)
	}

	loc, ok := section.Locate("body")
	if !ok {
		t.Fatal("body locator is missing")
	}

	if loc.Key != "nginx-1:48:req" || loc.Hint != "10.0.2.11:6379" {
		t.Fatalf("locator: %+v", loc)
	}

	if _, ok := section.Locate("args"); ok {
		t.Fatal("args is null and must not locate")
	}
}

// Точечная замена: всё, кроме обменника, обязано доехать байт в байт. Это то самое
// свойство, ради которого запись не разбирается в структуру.
func TestSpliceStoreKeepsEverythingElse(t *testing.T) {
	out, err := SpliceStore([]byte(retainDatagram), []byte(`{"headers":null}`))
	if err != nil {
		t.Fatal(err)
	}

	var got, want map[string]json.RawMessage

	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("spliced payload is not JSON: %s", out)
	}

	if err := json.Unmarshal([]byte(retainDatagram), &want); err != nil {
		t.Fatal(err)
	}

	if len(got) != len(want) {
		t.Fatalf("field count changed: %d != %d", len(got), len(want))
	}

	for key, value := range want {
		if key == "store" {
			continue
		}

		if string(got[key]) != string(value) {
			t.Fatalf("%s: %s != %s", key, got[key], value)
		}
	}

	if string(got["store"]) != `{"headers":null}` {
		t.Fatalf("store not replaced: %s", got["store"])
	}
}

// Слово "store" встречается и внутри локаторов, и в любом значении, которое
// оператор положил в waf_var. Поиском подстроки эту замену делать нельзя.
func TestSpliceStoreIgnoresNestedKeys(t *testing.T) {
	raw := `{"vars":{"store":"hot","note":"\"store\":{}"},` +
		`"store":{"body":null},"ray":"r"}`

	out, err := SpliceStore([]byte(raw), []byte(`{"body":{"size":1}}`))
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Vars struct {
			Store string `json:"store"`
			Note  string `json:"note"`
		} `json:"vars"`
		Store struct {
			Body map[string]any `json:"body"`
		} `json:"store"`
	}

	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("broken JSON: %s", out)
	}

	if got.Vars.Store != "hot" || got.Vars.Note != `"store":{}` {
		t.Fatalf("nested store touched: %s", out)
	}

	if got.Store.Body["size"] != float64(1) {
		t.Fatalf("top-level store not replaced: %s", out)
	}
}

// Обменника в записи нет — подставлять его агенту нечего.
func TestSpliceStoreWithoutSection(t *testing.T) {
	out, err := SpliceStore([]byte(moduleDatagram), []byte(`{"body":null}`))
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != moduleDatagram {
		t.Fatalf("record changed: %s", out)
	}
}

func TestReadressReplacesOnlyAddress(t *testing.T) {
	raw := json.RawMessage(`{"size":4096,"sha256":"9f86","complete":true,` +
		`"encoding":"identity","enc":{"kid":"2026-08"},"store":"hot",` +
		`"driver":"redis","key":"old","expires_at":1723753500,` +
		`"hint":"10.0.2.11:6379","future_field":7}`)

	out, err := Readdress(raw, "archive", "s3", "2026/08/15/n/r.body", 0)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got["store"] != "archive" || got["driver"] != "s3" {
		t.Fatalf("address: %s", out)
	}

	if got["key"] != "2026/08/15/n/r.body" {
		t.Fatalf("key: %s", out)
	}

	// Срок обменника и подсказка узла после переезда лгали бы: в архиве узла нет,
	// а срок там свой. Своего архив не назвал — значит поля нет вовсе.
	if _, ok := got["expires_at"]; ok {
		t.Fatalf("expires_at survived: %s", out)
	}

	if _, ok := got["hint"]; ok {
		t.Fatalf("hint survived: %s", out)
	}

	// Описательные поля верны независимо от того, где объект лежит.
	if got["size"] != float64(4096) || got["sha256"] != "9f86" {
		t.Fatalf("description lost: %s", out)
	}

	// Блок шифрования переезжает как есть: ключа агент не видит.
	if enc, ok := got["enc"].(map[string]any); !ok || enc["kid"] != "2026-08" {
		t.Fatalf("enc lost: %s", out)
	}

	// Поле, которого агент не знает, он не имеет права терять.
	if got["future_field"] != float64(7) {
		t.Fatalf("unknown field lost: %s", out)
	}
}

// Срок архива подменяет срок обменника, а не добавляется к нему: адресация в
// локаторе одна, и относится она к тому месту, где объект лежит сейчас.
func TestReaddressCarriesArchiveExpiry(t *testing.T) {
	raw := json.RawMessage(`{"size":96,"store":"hot","driver":"redis",` +
		`"key":"old","expires_at":1723753500,"hint":"h"}`)

	out, err := Readdress(raw, "archive", "s3", "2026/08/15/n/r.hdr", 1761004800)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got["expires_at"] != float64(1761004800) {
		t.Fatalf("archive expiry: %s", out)
	}
}

func TestUnreachableDropsAddress(t *testing.T) {
	raw := json.RawMessage(`{"size":96,"store":"hot","driver":"redis",` +
		`"key":"k","hint":"h"}`)

	out, err := Unreachable(raw, "expired")
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got["unavailable"] != "expired" {
		t.Fatalf("reason: %s", out)
	}

	for _, name := range locatorAddress {
		if _, ok := got[name]; ok {
			t.Fatalf("%s survived: %s", name, out)
		}
	}

	if got["size"] != float64(96) {
		t.Fatalf("size lost: %s", out)
	}

	// Причина -- первое поле: запись читают глазами, и «чего нет» важнее «сколько
	// весило».
	if !strings.HasPrefix(string(out), `{"unavailable":`) {
		t.Fatalf("order: %s", out)
	}
}

// Пересборка обменника сохраняет порядок видов и оставляет archive на месте: по
// нему видно, сколько объекту отмерено.
func TestStoreRenderKeepsShape(t *testing.T) {
	section, err := ParseStore([]byte(retainDatagram))
	if err != nil {
		t.Fatal(err)
	}

	out, err := section.Render()
	if err != nil {
		t.Fatal(err)
	}

	body := string(out)

	if !strings.HasPrefix(body, `{"headers":`) {
		t.Fatalf("kind order: %s", body)
	}

	if !strings.Contains(body, `"args":null`) {
		t.Fatalf("null locator lost: %s", body)
	}

	if !strings.Contains(body,
		`"archive":{"headers":{"ttl":2592000},"body":{"ttl":0,"limit":8192}}`) {
		t.Fatalf("archive lost: %s", body)
	}
}

// Урезанный агентом объект обязан объявить себя урезанным: без этого читатель
// принял бы префикс за оригинал. Размер описывает то, что лежит в архиве
// (docs/body-storage.md#локатор), а целое остаётся за sha256: пришедший за
// объектом получит ровно столько байт, сколько ему обещано.
func TestTrimmedMarksLocator(t *testing.T) {
	raw := json.RawMessage(`{"size":4096,"sha256":"9f86","complete":true,` +
		`"truncated":false,"store":"archive","driver":"s3","key":"o"}`)

	out, err := Trimmed(raw, 64)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got["truncated"] != true || got["complete"] != false {
		t.Fatalf("trim not marked: %s", out)
	}

	if got["size"] != float64(64) {
		t.Fatalf("size must describe what landed in the archive: %s", out)
	}

	if got["sha256"] != "9f86" {
		t.Fatalf("checksum of the whole object must survive: %s", out)
	}
}
