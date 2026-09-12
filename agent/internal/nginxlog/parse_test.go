package nginxlog

import (
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestParseErrorLine(t *testing.T) {
	raw := []byte(`<187>Aug 23 12:00:00 edge-01 nginx: 2026/08/23 12:00:00 [error] 29#29: ` +
		`*1 open() "/var/www/nope" failed (2: No such file or directory)`)

	line, ok := Parse(raw, at)
	if !ok {
		t.Fatal("строка не разобралась")
	}

	if line.Severity != "error" {
		t.Fatalf("severity: %q", line.Severity)
	}

	if line.Service != "nginx" {
		t.Fatalf("service: %q", line.Service)
	}

	if !strings.HasPrefix(line.Text, "2026/08/23 12:00:00 [error]") {
		t.Fatalf("text: %q", line.Text)
	}

	if !line.TS.Equal(at) {
		t.Fatalf("ts: %v", line.TS)
	}
}

// Тег — единственное, чем контур называет источник строки, и он же переживает
// nohostname: без имени хоста тег встаёт сразу после отметки времени.
func TestParseNoHostname(t *testing.T) {
	raw := []byte(`<190>Aug  3 09:04:05 nginx_access: 10.0.0.1 - - "GET /a HTTP/1.1" 200 12`)

	line, ok := Parse(raw, at)
	if !ok {
		t.Fatal("строка не разобралась")
	}

	if line.Service != "nginx_access" {
		t.Fatalf("service: %q", line.Service)
	}

	if line.Severity != "info" {
		t.Fatalf("severity: %q", line.Severity)
	}

	if line.Text != `10.0.0.1 - - "GET /a HTTP/1.1" 200 12` {
		t.Fatalf("text: %q", line.Text)
	}
}

/*
 * Двоеточий в access-строке сколько угодно: "GET /a?t=1: HTTP/1.1", время
 * ответа, порт апстрима. Тег ищется не дальше двух полей от отметки времени,
 * иначе сервисом станет случайное слово из середины запроса.
 */
func TestParseColonInText(t *testing.T) {
	raw := []byte(`<190>Aug 23 12:00:00 edge-01 nginx: - - upstream: 10.0.0.2:8080 rt=0.001`)

	line, _ := Parse(raw, at)

	if line.Service != "nginx" {
		t.Fatalf("service: %q", line.Service)
	}

	if line.Text != "- - upstream: 10.0.0.2:8080 rt=0.001" {
		t.Fatalf("text: %q", line.Text)
	}
}

// Чужой писатель в тот же сокет. Строку не выбрасываем: без уровня и с
// умолчанием в сервисе она всё равно отвечает на «что там было».
func TestParsePlainText(t *testing.T) {
	line, ok := Parse([]byte("just a line\n"), at)
	if !ok {
		t.Fatal("строка не разобралась")
	}

	if line.Severity != "" {
		t.Fatalf("severity: %q", line.Severity)
	}

	if line.Service != DefaultService {
		t.Fatalf("service: %q", line.Service)
	}

	if line.Text != "just a line" {
		t.Fatalf("text: %q", line.Text)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, ok := Parse([]byte("\n"), at); ok {
		t.Fatal("пустая датаграмма не должна давать строку")
	}
}

func TestParseTruncates(t *testing.T) {
	long := strings.Repeat("x", maxText+100)

	line, _ := Parse([]byte("<190>Aug 23 12:00:00 edge-01 nginx: "+long), at)

	if len(line.Text) != maxText {
		t.Fatalf("len: %d", len(line.Text))
	}
}
