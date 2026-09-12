package audit

import (
	"encoding/json"
	"testing"
)

// Датаграмма модуля по docs/messages/agent.schema.ts, укороченная до полей,
// которые проверяются здесь.
const moduleDatagram = `{"ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",` +
	`"node":"edge-01","phase":"request","ts":"2026-08-15T21:40:00.123Z",` +
	`"client_ip":"203.0.113.7","client_port":54233,` +
	`"http":{"method":"POST","scheme":"https","host":"shop.example.com",` +
	`"uri":"/api/orders","version":"HTTP/1.1","args_size":0,` +
	`"headers_size":288,"headers_count":9,"body_size":0,"status":403},` +
	`"route":{"server_name":"shop.example.com","location":"/api/"},` +
	`"verdict":"deny","code":"score","by":"module",` +
	`"score":{"total":80,"deny_at":50},` +
	`"inspectors":{"module":{"verdict":"deny"},` +
	`"modsec":{"verdict":"score","score":80,"weighted":80,"latency_ms":4}},` +
	`"vars":{"ua":"curl/8.5.0"},"waf_latency_us":8300}`

func TestSubject(t *testing.T) {
	if got := Subject("edge-01"); got != "waf.audit.request.edge-01" {
		t.Fatalf("Subject(edge-01) = %q", got)
	}

	if got := Subject(""); got != "waf.audit.request.unknown" {
		t.Fatalf("Subject(empty) = %q", got)
	}
}

func TestDecodeReadsRoutingFields(t *testing.T) {
	d, err := Decode([]byte(moduleDatagram))
	if err != nil {
		t.Fatal(err)
	}

	if d.Ray != "7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03" {
		t.Fatalf("ray: %q", d.Ray)
	}

	if d.Node != "edge-01" || d.Phase != "request" || d.Verdict != VerdictDeny {
		t.Fatalf("routing: %+v", d)
	}

	if d.Status != 403 {
		t.Fatalf("status: %d", d.Status)
	}
}

// Копия обязательна: буфер приёма переиспользуется следующей датаграммой.
func TestDecodeCopiesPayload(t *testing.T) {
	buf := []byte(moduleDatagram)

	d, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}

	for i := range buf {
		buf[i] = 'x'
	}

	var back map[string]any
	if err := json.Unmarshal(d.Raw, &back); err != nil {
		t.Fatalf("payload clobbered: %v", err)
	}
}

// Главное свойство агента: он ничего не теряет. Всё, что прислал модуль,
// доезжает до шины ровно в том же виде.
func TestEnvelopeKeepsEveryField(t *testing.T) {
	out, err := Envelope([]byte(moduleDatagram), "")
	if err != nil {
		t.Fatal(err)
	}

	var got, want map[string]any

	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("enveloped payload is not JSON: %v", err)
	}

	if err := json.Unmarshal([]byte(moduleDatagram), &want); err != nil {
		t.Fatal(err)
	}

	if got["v"] != float64(Version) || got["kind"] != Kind {
		t.Fatalf("envelope: v=%v kind=%v", got["v"], got["kind"])
	}

	delete(got, "v")
	delete(got, "kind")

	if len(got) != len(want) {
		t.Fatalf("field count changed: %d != %d", len(got), len(want))
	}

	for key, value := range want {
		a, _ := json.Marshal(value)
		b, _ := json.Marshal(got[key])

		if string(a) != string(b) {
			t.Fatalf("%s: %s != %s", key, b, a)
		}
	}
}

// Секции store с локаторами в старом конверте не было вовсе — агент её терял.
func TestEnvelopeKeepsStoreLocators(t *testing.T) {
	raw := `{"ray":"r","node":"n","verdict":"deny",` +
		`"store":{"headers":{"store":"hot","driver":"redis","key":"k","size":96},` +
		`"args":null,"body":{"size":4096,"truncated":false}}}`

	out, err := Envelope([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Store *struct {
			Headers map[string]any `json:"headers"`
			Body    map[string]any `json:"body"`
		} `json:"store"`
	}

	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got.Store == nil || got.Store.Headers["key"] != "k" {
		t.Fatalf("store lost: %s", out)
	}

	if got.Store.Body["size"] != float64(4096) {
		t.Fatalf("body locator lost: %s", out)
	}
}

func TestEnvelopeInjectsNodeWhenMissing(t *testing.T) {
	out, err := Envelope([]byte(`{"ray":"r","verdict":"allow"}`), "edge-01")
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}

	if got["node"] != "edge-01" {
		t.Fatalf("node: %s", out)
	}
}

func TestEnvelopeRejectsNonObject(t *testing.T) {
	for _, raw := range []string{"", "[]", "null", "not json"} {
		if _, err := Envelope([]byte(raw), ""); err == nil {
			t.Fatalf("%q must be rejected", raw)
		}
	}
}

func TestEnvelopeEmptyObject(t *testing.T) {
	out, err := Envelope([]byte("{}"), "")
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("broken JSON for empty object: %s", out)
	}

	if got["kind"] != Kind {
		t.Fatalf("envelope: %s", out)
	}
}

// Узел не должен появиться в записи дважды: разбор берёт последнее значение,
// и смысл записи зависел бы от порядка полей.
func TestPublishDoesNotDuplicateNode(t *testing.T) {
	d, err := Decode([]byte(moduleDatagram))
	if err != nil {
		t.Fatal(err)
	}

	if !hasNode(d.Raw) {
		t.Fatal("module datagram carries node")
	}

	out, err := Envelope(d.Raw, "")
	if err != nil {
		t.Fatal(err)
	}

	var count int
	var probe map[string]json.RawMessage

	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatal(err)
	}

	for key := range probe {
		if key == "node" {
			count++
		}
	}

	if count != 1 {
		t.Fatalf("node appears %d times: %s", count, out)
	}
}

/*
 * Приёмник без соединения молчит, а не ошибается: агент без шины продолжает
 * вести архив и пульс, и запись, которую некуда отправить, не должна ронять
 * обработчик сокета вердиктов.
 */
func TestAddWithoutConnIsSilent(t *testing.T) {
	var s *Sink

	if err := s.Add(Decision{Ray: "a", Node: "n", Verdict: VerdictAllow}); err != nil {
		t.Fatalf("nil sink: %v", err)
	}

	empty := &Sink{}

	if err := empty.Add(Decision{Ray: "a", Node: "n", Verdict: VerdictAllow}); err != nil {
		t.Fatalf("nil conn: %v", err)
	}

	if err := empty.Add(Decision{}); err != nil {
		t.Fatalf("empty: %v", err)
	}

	if len(empty.pending) != 0 {
		t.Errorf("pending = %d, want none", len(empty.pending))
	}
}
