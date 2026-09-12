/*
 * Списки waf_archive allow= / mask= / deny= применяет агент: в Redis лежит
 * либо вид инспекторов (без reload), либо оригинал (reload). Модуль эти
 * списки в обменник не режет.
 *
 * Вид инспекторов уже прошёл маску снимка: значения названных в ней имён --
 * sha256. Модуль перечисляет их в hashed, и маска архива на такое имя
 * оставляет значение как есть: хеш от хеша не сошёлся бы ни с записью, ни с
 * тем, что видели инспекторы.
 */

package retain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/exemt/placitum-node/agent/internal/audit"
)

func applyTerms(kind string, data []byte, terms audit.Terms) ([]byte, error) {
	if kind == "body" || !hasLists(terms) {
		return data, nil
	}

	switch kind {
	case "headers":
		return filterHeaders(data, terms)
	case "args":
		return filterArgs(data, terms)
	default:
		return data, nil
	}
}

func hasLists(t audit.Terms) bool {
	return len(t.Allow) > 0 || len(t.Mask) > 0 || len(t.Deny) > 0
}

func listed(list []string, name string) bool {
	for _, item := range list {
		if strings.EqualFold(item, name) {
			return true
		}
	}
	return false
}

func keepName(name string, terms audit.Terms) bool {
	if listed(terms.Deny, name) {
		return false
	}
	if len(terms.Allow) == 0 {
		return true
	}
	return listed(terms.Allow, name)
}

func hashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// maskValue — значение под маской архива: хеш, если оно ещё не хеш.
func maskValue(name, value string, terms audit.Terms) string {
	if listed(terms.Hashed, name) {
		return value
	}
	return hashValue(value)
}

func filterHeaders(data []byte, terms audit.Terms) ([]byte, error) {
	var pairs [][]string
	if err := json.Unmarshal(data, &pairs); err != nil {
		return nil, fmt.Errorf("archive headers: %w", err)
	}

	out := make([][]string, 0, len(pairs))
	for _, pair := range pairs {
		if len(pair) < 1 {
			continue
		}
		name := pair[0]
		if !keepName(name, terms) {
			continue
		}
		value := ""
		if len(pair) > 1 {
			value = pair[1]
		}
		if listed(terms.Mask, name) {
			value = maskValue(name, value, terms)
		}
		out = append(out, []string{name, value})
	}

	return json.Marshal(out)
}

func filterArgs(data []byte, terms audit.Terms) ([]byte, error) {
	src := string(data)
	if src == "" {
		return data, nil
	}

	var b strings.Builder
	first := true

	for _, part := range strings.Split(src, "&") {
		name, value, hadEq := splitArg(part)
		if name == "" || !keepName(name, terms) {
			continue
		}
		if listed(terms.Mask, name) {
			value = maskValue(name, value, terms)
			hadEq = true
		}
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(name)
		if hadEq {
			b.WriteByte('=')
			b.WriteString(value)
		}
	}

	return []byte(b.String()), nil
}

func splitArg(part string) (name, value string, hadEq bool) {
	if i := strings.IndexByte(part, '='); i >= 0 {
		return part[:i], part[i+1:], true
	}
	return part, "", false
}
