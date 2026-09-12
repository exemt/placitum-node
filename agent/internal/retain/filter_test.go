package retain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/exemt/placitum-node/agent/internal/audit"
)

func TestFilterHeadersDenyAndMask(t *testing.T) {
	in := `[["Host","a"],["Cookie","secret"],["X-Api-Key","k"]]`
	out, err := applyTerms("headers", []byte(in), audit.Terms{
		Deny: []string{"x-api-key"},
		Mask: []string{"cookie"},
	})
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte("secret"))
	want := `[["Host","a"],["Cookie","` + hex.EncodeToString(sum[:]) + `"]]`
	if string(out) != want {
		t.Fatalf("got %s want %s", out, want)
	}
}

func TestFilterHeadersAllow(t *testing.T) {
	in := `[["Host","a"],["Content-Type","json"],["X-Api-Key","k"]]`
	out, err := applyTerms("headers", []byte(in), audit.Terms{
		Allow: []string{"host", "content-type"},
		Deny:  []string{"content-type"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != `[["Host","a"]]` {
		t.Fatalf("deny wins over allow: %s", out)
	}
}

func TestFilterArgsInheritShape(t *testing.T) {
	in := []byte("q=1&session=abc&token=zzz")
	out, err := applyTerms("args", in, audit.Terms{Deny: []string{"token"}})
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != "q=1&session=abc" {
		t.Fatalf("args: %s", out)
	}
}

func TestFilterBodyUntouched(t *testing.T) {
	in := []byte("raw-body")
	out, err := applyTerms("body", in, audit.Terms{Deny: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "raw-body" {
		t.Fatalf("body: %s", out)
	}
}

func TestFilterNoListsPassthrough(t *testing.T) {
	in := []byte(`[["Host","a"]]`)
	out, err := applyTerms("headers", in, audit.Terms{TTL: 30})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("passthrough: %s", out)
	}
}

/*
 * Маска архива на имя, которое маска снимка уже хешировала (объект в Redis --
 * вид инспекторов, reload его не перекладывал): значение остаётся тем же
 * хешем, а не хешем от хеша. Соседнее имя, которого снимок не трогал,
 * хешируется как обычно.
 */
func TestFilterHeadersMaskAlreadyHashed(t *testing.T) {
	already := hashValue("secret")
	in := `[["Cookie","` + already + `"],["X-Token","tok"]]`
	out, err := applyTerms("headers", []byte(in), audit.Terms{
		Mask:   []string{"cookie", "x-token"},
		Hashed: []string{"Cookie"},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := `[["Cookie","` + already + `"],["X-Token","` + hashValue("tok") + `"]]`
	if string(out) != want {
		t.Fatalf("got %s want %s", out, want)
	}
}

func TestFilterArgsMaskAlreadyHashed(t *testing.T) {
	already := hashValue("zzz")
	in := []byte("q=1&token=" + already + "&session=abc")
	out, err := applyTerms("args", in, audit.Terms{
		Mask:   []string{"token", "session"},
		Hashed: []string{"token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "q=1&token=" + already + "&session=" + hashValue("abc")
	if string(out) != want {
		t.Fatalf("got %s want %s", out, want)
	}
}
