/*
 * Уровень журнала процесса.
 *
 * Словарь -- error_log nginx без emerg: debug, info, notice, warn, error,
 * crit, alert. Тот же, что у инспекторов (inspectors/<имя>/internal/loglevel),
 * у каталога и у документа policy/log-levels: оператор ставит уровень краю,
 * инспектору и сервису одними словами, ничего не переводя. Три слова поверх
 * четырёх стандартных у slog -- notice между info и warn, crit и alert выше
 * error -- существуют как пороги: сам процесс пишет только
 * debug/info/warn/error, поэтому notice режет то же, что warn, а crit и alert
 * глушат журнал целиком.
 */

package logkit

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const (
	// Notice -- между info и warn: у slog между ними четыре деления.
	Notice slog.Level = slog.LevelInfo + 2
	// Crit и Alert -- выше error. Процесс на них не пишет, это только пороги.
	Crit  slog.Level = slog.LevelError + 4
	Alert slog.Level = slog.LevelError + 8
)

// Порядок -- от болтливого к тихому, он же порядок словаря nginx.
var table = [...]struct {
	name  string
	level slog.Level
}{
	{"debug", slog.LevelDebug},
	{"info", slog.LevelInfo},
	{"notice", Notice},
	{"warn", slog.LevelWarn},
	{"error", slog.LevelError},
	{"crit", Crit},
	{"alert", Alert},
}

// Names -- словарь в порядке от болтливого к тихому.
func Names() []string {
	out := make([]string, 0, len(table))

	for _, row := range table {
		out = append(out, row.name)
	}

	return out
}

/*
 * Parse -- имя уровня в порог. "warning" принимается как warn ради старых
 * значений переменных окружения; в словарь оно не входит, и контроллер его не
 * шлёт. Регистр не важен: старые значения писались и как у slog, заглавными.
 */
func Parse(s string) (slog.Level, error) {
	name := strings.ToLower(strings.TrimSpace(s))

	if name == "warning" {
		name = "warn"
	}

	for _, row := range table {
		if row.name == name {
			return row.level, nil
		}
	}

	return 0, fmt.Errorf("expected one of %s, got %q",
		strings.Join(Names(), ", "), s)
}

// String -- имя порога словами nginx; чужое значение печатается как у slog.
func String(level slog.Level) string {
	for _, row := range table {
		if row.level == level {
			return row.name
		}
	}

	return level.String()
}

/*
 * Env -- стартовый порог из переменной окружения процесса (WAF_AGENT_LOG,
 * WAF_LOGGER_LOG, ...). Пусто -- fallback. Чужое слово -- ошибка старта с
 * именем переменной: процесс, молча севший на info вместо заказанного debug,
 * отнимает ровно то расследование, ради которого debug и заказывали.
 */
func Env(name, fallback string) (slog.Level, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		value = fallback
	}

	level, err := Parse(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return level, nil
}
