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

// cutToLimit shortens the object to the archive size. The body is a byte
// prefix; headers and the query string keep whole pairs, so the archived
// object still parses: a JSON array cut in the middle of a pair is not a
// shorter object but a broken one.
func cutToLimit(kind string, data []byte, limit int64) ([]byte, bool) {
	if limit <= 0 || int64(len(data)) <= limit {
		return data, false
	}

	switch kind {
	case "headers":
		return cutHeaders(data, limit), true
	case "args":
		return cutArgs(data, limit), true
	default:
		return data[:limit], true
	}
}

func cutHeaders(data []byte, limit int64) []byte {
	var pairs [][]string
	if err := json.Unmarshal(data, &pairs); err != nil {
		return data[:limit]
	}

	out := make([][]string, 0, len(pairs))
	size := int64(2)

	for _, pair := range pairs {
		raw, err := json.Marshal(pair)
		if err != nil {
			continue
		}

		add := int64(len(raw))
		if len(out) > 0 {
			add++
		}

		if size+add > limit {
			break
		}

		out = append(out, pair)
		size += add
	}

	cut, err := json.Marshal(out)
	if err != nil {
		return data[:limit]
	}

	return cut
}

func cutArgs(data []byte, limit int64) []byte {
	cut := data[:limit]

	if limit < int64(len(data)) && data[limit] == '&' {
		return cut
	}

	if i := strings.LastIndexByte(string(cut), '&'); i > 0 {
		return cut[:i]
	}

	return cut
}
