package desired

import (
	"os"
	"path/filepath"
	"testing"
)

/*
Форма отпечатка -- договор с модулем: воркер кладёт в присутствие
`md5:<32 hex>` (ngx_http_waf_presence_hash), и панель сравнивает строки как
есть. Ожидание здесь -- вывод стороннего md5sum, а не пересчёт тем же кодом:
иначе тест подтверждал бы сам себя.
*/
func TestFingerprintMatchesModuleForm(t *testing.T) {
	got := Fingerprint([]byte("worker_processes 2;\n"))
	want := "md5:4048b96f772a8b66017cecb6d4d4d161"

	if got != want {
		t.Fatalf("fingerprint %q, want %q", got, want)
	}
	if other := Fingerprint([]byte("worker_processes 3;\n")); other == got {
		t.Fatal("fingerprint did not change with the body")
	}
}

func TestFingerprintFileMatchesBody(t *testing.T) {
	dir := t.TempDir()
	body := []byte("events {}\nhttp {}\n")

	if err := os.WriteFile(LiveConfPath(dir), body, 0o644); err != nil {
		t.Fatal(err)
	}

	if got, want := FingerprintFile(LiveConfPath(dir)), Fingerprint(body); got != want {
		t.Fatalf("file fingerprint %q, body %q", got, want)
	}
}

// Нечитаемый файл -- пустая строка, а не отпечаток пустоты: кадр без поля
// прячет колонку, кадр с md5 пустого файла соврал бы про расхождение.
func TestFingerprintFileMissing(t *testing.T) {
	if got := FingerprintFile(filepath.Join(t.TempDir(), "nginx.conf")); got != "" {
		t.Fatalf("missing file gave %q", got)
	}
}

// Затравка состояния: до первого apply отпечаток берётся с диска, поколения
// при этом нет.
func TestNewAppliedSeedsFromDisk(t *testing.T) {
	dir := t.TempDir()
	body := []byte("events {}\n")

	if err := os.WriteFile(LiveConfPath(dir), body, 0o644); err != nil {
		t.Fatal(err)
	}

	hash, rev, apply, conf := NewApplied(dir).Snapshot()

	if hash != "" || rev != 0 || apply != "" {
		t.Fatalf("seeded generation: hash %q rev %d apply %q", hash, rev, apply)
	}
	if conf != Fingerprint(body) {
		t.Fatalf("seeded conf %q, want %q", conf, Fingerprint(body))
	}
}
