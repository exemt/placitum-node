package rps

import "testing"

func TestRoutesSplitsByServerAndLocation(t *testing.T) {
	var now int64 = 1_000
	r := &Routes{rows: map[Route]*Counter{}, max: MaxRoutes, now: func() int64 { return now }}

	for i := 0; i < 20; i++ {
		r.Add("shop.example.com", "/api/", "", 200, "allow")
	}
	for i := 0; i < 10; i++ {
		r.Add("shop.example.com", "/static/", "", 404, "allow")
	}
	for i := 0; i < 5; i++ {
		r.Add("api.example.com", "/", "", 503, "deny")
	}

	rows := r.Snapshot()
	if len(rows) != 3 {
		t.Fatalf("routes = %d, want 3", len(rows))
	}

	// Порядок -- по серверу, затем по пути.
	if rows[0].Server != "api.example.com" || rows[1].Location != "/api/" {
		t.Fatalf("order = %+v", rows)
	}
	if rows[1].RPS != 2 || rows[1].Codes.XX2 != 2 {
		t.Fatalf("/api/ = %+v, want 2 rps all 2xx", rows[1])
	}
	if rows[2].RPS != 1 || rows[2].Codes.XX4 != 1 {
		t.Fatalf("/static/ = %+v, want 1 rps all 4xx", rows[2])
	}
	if rows[0].Codes.XX5 != 0.5 {
		t.Fatalf("api 5xx = %+v, want 0.5", rows[0])
	}
}

func TestRoutesDropSilent(t *testing.T) {
	var now int64 = 1_000
	r := &Routes{rows: map[Route]*Counter{}, max: MaxRoutes, now: func() int64 { return now }}

	r.Add("gone.example.com", "/", "", 200, "allow")
	if len(r.Snapshot()) != 1 {
		t.Fatalf("fresh route missing")
	}

	now += Window
	if rows := r.Snapshot(); len(rows) != 0 {
		t.Fatalf("silent route kept: %+v", rows)
	}
	if len(r.rows) != 0 {
		t.Fatalf("silent counter kept: %d", len(r.rows))
	}
}

/*
 * Потолок держит карту, а не считалку ноды: новый ключ на полной карте
 * отбрасывается и попадает в dropped, но итог ноды считает отдельный Counter,
 * и он этого не замечает.
 */
func TestRoutesCapIsCountedNotSilent(t *testing.T) {
	var now int64 = 1_000
	r := &Routes{rows: map[Route]*Counter{}, max: 2, now: func() int64 { return now }}

	r.Add("a", "/", "", 200, "allow")
	r.Add("b", "/", "", 200, "allow")
	r.Add("c", "/", "", 200, "allow")

	if len(r.Snapshot()) != 2 {
		t.Fatalf("cap not held")
	}
	if r.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", r.Dropped())
	}

	// Место освобождается, как только прежние ключи замолчали.
	now += Window
	r.Add("c", "/", "", 200, "allow")
	rows := r.Snapshot()
	if len(rows) != 1 || rows[0].Server != "c" {
		t.Fatalf("after eviction: %+v", rows)
	}
}

func TestRoutesIgnoresEmptyKey(t *testing.T) {
	r := NewRoutes()
	r.Add("", "", "", 200, "allow")

	if len(r.Snapshot()) != 0 {
		t.Fatalf("empty route counted")
	}
}

func TestRoutesSplitByID(t *testing.T) {
	var now int64 = 1_000
	r := &Routes{rows: map[Route]*Counter{}, max: MaxRoutes, now: func() int64 { return now }}

	// Одно имя блока, два uuid: два перехватчика без server_name с корнем у
	// каждого. Имена совпали, маршруты панели разные -- складывать нельзя.
	for i := 0; i < 4; i++ {
		r.Add("_", "/", "aaaa", 200, "allow")
	}
	for i := 0; i < 2; i++ {
		r.Add("_", "/", "bbbb", 200, "allow")
	}

	rows := r.Snapshot()
	if len(rows) != 2 {
		t.Fatalf("routes = %d, want 2: %+v", len(rows), rows)
	}
	if rows[0].ID != "aaaa" || rows[0].RPS != 0.4 || rows[1].ID != "bbbb" || rows[1].RPS != 0.2 {
		t.Fatalf("split by id = %+v", rows)
	}
}
