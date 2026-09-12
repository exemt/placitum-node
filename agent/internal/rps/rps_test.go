package rps

import "testing"

func TestRateIsSumOverTenSeconds(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	for i := 0; i < 20; i++ {
		c.Add(200, "allow")
	}

	if got := c.Rate(); got != 2 {
		t.Fatalf("20 hits in one second: rate = %v, want 2", got)
	}

	now += 3
	if got := c.Rate(); got != 2 {
		t.Fatalf("same window: rate = %v, want 2", got)
	}

	now += 7
	if got := c.Rate(); got != 0 {
		t.Fatalf("after 10s: rate = %v, want 0", got)
	}
}

func TestEmptyIsZero(t *testing.T) {
	c := New()
	if c.Rate() != 0 {
		t.Fatalf("empty: %v", c.Rate())
	}
	if got := c.Status(); got != (StatusRates{}) {
		t.Fatalf("empty status: %+v", got)
	}
}

func TestStatusClasses(t *testing.T) {
	var now int64 = 1_000
	c := &Counter{now: func() int64 { return now }}

	for i := 0; i < 10; i++ {
		c.Add(0, "allow")
	}
	for i := 0; i < 5; i++ {
		c.Add(303, "redirect")
	}
	for i := 0; i < 4; i++ {
		c.Add(403, "deny")
	}
	c.Add(503, "deny")

	if got := c.Rate(); got != 2 {
		t.Fatalf("total: %v, want 2", got)
	}
	got := c.Status()
	if got.XX2 != 1 || got.XX3 != 0.5 || got.XX4 != 0.4 || got.XX5 != 0.1 {
		t.Fatalf("status = %+v, want 1 / 0.5 / 0.4 / 0.1", got)
	}

	now += 10
	if got := c.Status(); got != (StatusRates{}) {
		t.Fatalf("after 10s: %+v", got)
	}
}

func TestClass(t *testing.T) {
	cases := []struct {
		status  int
		verdict string
		want    int
	}{
		{200, "allow", 2},
		{0, "allow", 2},
		{303, "redirect", 3},
		{0, "redirect", 3},
		{403, "deny", 4},
		{0, "deny", 4},
		{503, "deny", 5},
		{0, "timeout", 0},
	}
	for _, tc := range cases {
		if got := Class(tc.status, tc.verdict); got != tc.want {
			t.Fatalf("Class(%d, %q) = %d, want %d", tc.status, tc.verdict, got, tc.want)
		}
	}
}
