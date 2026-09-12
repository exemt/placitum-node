/*
 * Разбор датаграммы, которую nginx кладёт в сокет логов.
 *
 * Формат — RFC 3164, тот, что пишет ngx_syslog.c:
 *
 *     <PRI>Mmm dd hh:mm:ss hostname tag: текст
 *
 * Приоритет даёт уровень: access-лог приезжает на info, ошибки — на своём.
 * Тег даёт сервис: имя канала задаётся в самой директиве nginx (`tag=`), и
 * это единственное место, где контур может назвать источник строки, не
 * разбирая её содержимое.
 *
 * Время строки берём своё, а не из шапки: в RFC 3164 нет ни года, ни зоны, ни
 * долей секунды, и восстановленная из неё отметка была бы хуже той, что стоит
 * в момент приёма. Собственная отметка nginx остаётся внутри текста — и у
 * error_log, и у access_log с $time_local, — то есть ничего не теряется.
 */

package nginxlog

import (
	"strings"
	"time"
)

// DefaultService — чем подписывается строка, у которой тега не оказалось.
// Пустое поле здесь было бы хуже: по нему нельзя ни отфильтровать, ни понять,
// что источник тот же nginx, просто без `tag=`.
const DefaultService = "nginx"

// maxText — потолок текста строки. Сам nginx режет датаграмму примерно на
// двух килобайтах; запас здесь на случай чужого писателя в тот же сокет.
const maxText = 8 << 10

// severities — имена уровней syslog по индексу. Наружу уезжает имя, а не
// число: в фильтре и в таблице читают «error», а не «3».
var severities = [8]string{
	"emerg", "alert", "crit", "error", "warn", "notice", "info", "debug",
}

// Line — одна строка лога, как её увидит обменник.
type Line struct {
	TS       time.Time `json:"ts"`
	Service  string    `json:"service"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
}

/*
 * Parse разбирает датаграмму. Не разобралось — не ошибка: строка всё равно
 * едет, просто целиком в text и без уровня. Молча выбросить лог, потому что
 * его шапка не та, значит потерять ровно то, ради чего в сокет смотрят.
 */
func Parse(raw []byte, at time.Time) (Line, bool) {
	line := Line{TS: at, Service: DefaultService}

	body := strings.TrimRight(string(raw), "\x00\r\n")
	if body == "" {
		return Line{}, false
	}

	rest := body

	if pri, tail, ok := priority(rest); ok {
		line.Severity = severities[pri%8]
		rest = tail
	}

	if service, tail, ok := head(rest); ok {
		line.Service = service
		rest = tail
	}

	if len(rest) > maxText {
		rest = rest[:maxText]
	}

	line.Text = rest

	return line, rest != ""
}

// priority снимает "<190>" и отдаёт значение PRI. Facility нам не нужна:
// nginx кладёт её из `facility=` директивы, и на вопрос «откуда строка» уже
// ответил тег.
func priority(s string) (int, string, bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, s, false
	}

	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return 0, s, false
	}

	pri := 0

	for i := 1; i < end; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, s, false
		}
		pri = pri*10 + int(c-'0')
	}

	if pri > 191 {
		return 0, s, false
	}

	return pri, s[end+1:], true
}

/*
 * head снимает "Mmm dd hh:mm:ss [hostname] tag:" и отдаёт тег.
 *
 * Поле с двоеточием ищется не дальше двух шагов от отметки времени: с
 * `nohostname` тег стоит первым, без него — вторым, а дальше начинается текст,
 * в котором двоеточий сколько угодно. Без этого потолка «*1 open() failed» из
 * error_log отдал бы «failed» за имя сервиса.
 */
func head(s string) (string, string, bool) {
	rest := s

	for i := 0; i < 3; i++ {
		_, tail, ok := field(rest)
		if !ok {
			return "", s, false
		}
		rest = tail
	}

	for i := 0; i < 2; i++ {
		tok, tail, ok := field(rest)
		if !ok {
			return "", s, false
		}

		rest = tail

		if name, cut := strings.CutSuffix(tok, ":"); cut && name != "" {
			return name, rest, true
		}
	}

	return "", s, false
}

// field снимает одно поле, разделённое пробелами, и отдаёт остаток уже без
// ведущих пробелов.
func field(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}

	at := strings.IndexByte(s, ' ')
	if at < 0 {
		return s, "", true
	}

	return s[:at], strings.TrimLeft(s[at+1:], " "), true
}
