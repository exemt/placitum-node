/*
 * Формат пачки проверяется с обеих сторон одним набором: агент упаковывает,
 * Unpack разбирает, и элемент обязан совпасть байт в байт с тем, что уехало бы
 * отдельным сообщением. Это и есть весь контракт с потребителем -- на другой
 * стороне (logger/internal/model) лежит его зеркало.
 */

package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/nats-io/nats.go"
)

func decision(ray, node string) Decision {
	return Decision{
		Ray:     ray,
		Node:    node,
		Phase:   PhaseRequest,
		Verdict: VerdictAllow,
		Raw:     []byte(`{"ray":"` + ray + `","phase":"request","verdict":"allow"}`),
	}
}

func TestPackKeepsRecordsByteForByte(t *testing.T) {
	d := decision("r1", "edge-01")

	alone, err := Envelope(d.Raw, d.Node)
	if err != nil {
		t.Fatal(err)
	}

	body, err := pack("edge-01", []item{{node: "edge-01", body: alone}})
	if err != nil {
		t.Fatal(err)
	}

	items, ok := Unpack(body)
	if !ok {
		t.Fatal("packed batch does not read back as a batch")
	}

	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}

	if !bytes.Equal(items[0], alone) {
		t.Errorf("item = %s\nwant   = %s", items[0], alone)
	}
}

func TestPackEnvelopeIsABatch(t *testing.T) {
	body, err := pack("edge-01", []item{
		{node: "edge-01", body: []byte(`{"kind":"request","ray":"r1"}`)},
		{node: "edge-01", body: []byte(`{"kind":"request","ray":"r2"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	var env struct {
		V     int               `json:"v"`
		Kind  string            `json:"kind"`
		Node  string            `json:"node"`
		Items []json.RawMessage `json:"items"`
	}

	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}

	if env.Kind != KindBatch {
		t.Errorf("kind = %q, want %q", env.Kind, KindBatch)
	}

	if env.V != Version {
		t.Errorf("v = %d, want %d", env.V, Version)
	}

	if env.Node != "edge-01" {
		t.Errorf("node = %q, want edge-01", env.Node)
	}

	if len(env.Items) != 2 {
		t.Errorf("items = %d, want 2", len(env.Items))
	}
}

// Одиночное сообщение пачкой не притворяется: старый формат обязан остаться
// отличимым, иначе разбор на той стороне зависел бы от догадки.
func TestUnpackRejectsPlainRecord(t *testing.T) {
	one, err := Envelope([]byte(`{"ray":"r1"}`), "edge-01")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := Unpack(one); ok {
		t.Error("a plain record must not read as a batch")
	}

	if _, ok := Unpack(nil); ok {
		t.Error("an empty payload must not read as a batch")
	}
}

// Записи разных узлов не смешиваются в одном сообщении: субъект считается по
// записи, и пачка узла А на субъекте узла Б потерялась бы для потребителя.
func TestGroupByNodeSplitsAndKeepsOrder(t *testing.T) {
	order, byNode := groupByNode([]item{
		{node: "edge-01", body: []byte(`{"ray":"r1"}`)},
		{node: "edge-02", body: []byte(`{"ray":"r2"}`)},
		{node: "edge-01", body: []byte(`{"ray":"r3"}`)},
	})

	if len(order) != 2 || order[0] != "edge-01" || order[1] != "edge-02" {
		t.Fatalf("order = %v, want edge-01 before edge-02", order)
	}

	if len(byNode["edge-01"]) != 2 || len(byNode["edge-02"]) != 1 {
		t.Errorf("groups = %d / %d, want 2 and 1",
			len(byNode["edge-01"]), len(byNode["edge-02"]))
	}
}

// Запись без обязательных полей на шину не едет: субъект по пустому узлу не
// собирается, а склейка по пустому ray ничего не склеит.
func TestAddSkipsIncompleteRecords(t *testing.T) {
	// Соединение нужно только затем, чтобы Add не счёл приёмник выключенным:
	// отправкой здесь никто не занимается -- горутина пачки не запущена.
	s := &Sink{nc: &nats.Conn{}}

	for _, d := range []Decision{
		{Node: "edge-01", Verdict: VerdictAllow},
		{Ray: "r1", Verdict: VerdictAllow},
		{Ray: "r1", Node: "edge-01"},
	} {
		if err := s.Add(d); err != nil {
			t.Fatalf("Add(%+v) = %v, want a silent skip", d, err)
		}
	}

	if len(s.pending) != 0 {
		t.Errorf("pending = %d, want none", len(s.pending))
	}
}

// Переполнение буфера режет голову и считается: молча терять аудит нельзя.
func TestAddDropsOldestAndCounts(t *testing.T) {
	s := &Sink{nc: &nats.Conn{}}

	for i := 0; i < maxPending+10; i++ {
		d := decision("r", "edge-01")

		if err := s.Add(d); err != nil {
			t.Fatal(err)
		}

		// Отправлять некому: тест держит буфер, а не шину.
		if len(s.pending) > maxPending {
			t.Fatalf("pending = %d, want at most %d", len(s.pending), maxPending)
		}
	}

	if s.Dropped() != 10 {
		t.Errorf("dropped = %d, want 10", s.Dropped())
	}

	if s.size != sizeOf(s.pending) {
		t.Errorf("size = %d, want %d: the running size drifted from the buffer",
			s.size, sizeOf(s.pending))
	}
}
