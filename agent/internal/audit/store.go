package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
)

var Kinds = []string{"headers", "args", "body"}

var Suffix = map[string]string{
	"headers": "hdr",
	"args":    "arg",
	"body":    "body",
}

type Locator struct {
	Store  string `json:"store"`
	Driver string `json:"driver"`
	Key    string `json:"key"`
	Hint   string `json:"hint"`
}

type Terms struct {
	TTL int64 `json:"ttl"`

	Limit int64 `json:"limit,omitempty"`

	Allow []string `json:"allow,omitempty"`
	Mask  []string `json:"mask,omitempty"`
	Deny  []string `json:"deny,omitempty"`

	Hashed []string `json:"hashed,omitempty"`
}

type Store struct {
	Locators map[string]json.RawMessage

	Archive map[string]Terms
}

func ParseStore(raw []byte) (Store, error) {
	var doc struct {
		Store map[string]json.RawMessage `json:"store"`
	}

	if err := json.Unmarshal(raw, &doc); err != nil {
		return Store{}, err
	}

	if doc.Store == nil {
		return Store{}, nil
	}

	out := Store{Locators: make(map[string]json.RawMessage, len(Kinds))}

	for _, kind := range Kinds {
		if v, ok := doc.Store[kind]; ok {
			out.Locators[kind] = v
		}
	}

	if v, ok := doc.Store["archive"]; ok {
		if err := json.Unmarshal(v, &out.Archive); err != nil {
			return Store{}, fmt.Errorf("audit: store.archive: %w", err)
		}
	}

	return out, nil
}

func (s Store) Locate(kind string) (Locator, bool) {
	raw, ok := s.Locators[kind]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return Locator{}, false
	}

	var loc Locator
	if err := json.Unmarshal(raw, &loc); err != nil {
		return Locator{}, false
	}

	return loc, loc.Key != ""
}

func (s Store) Render() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte('{')

	for i, kind := range Kinds {
		if i != 0 {
			buf.WriteByte(',')
		}

		buf.WriteString(`"` + kind + `":`)

		if raw, ok := s.Locators[kind]; ok && len(raw) != 0 {
			buf.Write(raw)
		} else {
			buf.WriteString("null")
		}
	}

	if len(s.Archive) != 0 {
		buf.WriteString(`,"archive":{`)

		first := true
		for _, kind := range Kinds {
			terms, ok := s.Archive[kind]
			if !ok {
				continue
			}

			if !first {
				buf.WriteByte(',')
			}
			first = false

			buf.WriteString(`"` + kind + `":{"ttl":`)
			buf.WriteString(strconv.FormatInt(terms.TTL, 10))

			if terms.Limit > 0 {
				buf.WriteString(`,"limit":`)
				buf.WriteString(strconv.FormatInt(terms.Limit, 10))
			}

			writeNames := func(field string, names []string) {
				if len(names) == 0 {
					return
				}

				buf.WriteString(`,"` + field + `":[`)
				for i, n := range names {
					if i > 0 {
						buf.WriteByte(',')
					}
					raw, _ := json.Marshal(n)
					buf.Write(raw)
				}
				buf.WriteByte(']')
			}

			writeNames("allow", terms.Allow)
			writeNames("mask", terms.Mask)
			writeNames("deny", terms.Deny)
			writeNames("hashed", terms.Hashed)

			buf.WriteByte('}')
		}

		buf.WriteByte('}')
	}

	buf.WriteByte('}')

	return buf.Bytes(), nil
}

var locatorOrder = []string{
	"unavailable", "size", "declared_size", "sha256",
	"complete", "truncated", "encoding", "enc",
	"store", "driver", "key", "expires_at", "hint",
}

var locatorAddress = []string{"store", "driver", "key", "expires_at", "hint"}

func Readdress(raw json.RawMessage, store, driver, key string,
	expiresAt int64) (json.RawMessage, error) {

	fields, err := locatorFields(raw)
	if err != nil {
		return nil, err
	}

	for _, name := range locatorAddress {
		delete(fields, name)
	}

	fields["store"] = mustQuote(store)
	fields["driver"] = mustQuote(driver)
	fields["key"] = mustQuote(key)

	if expiresAt > 0 {
		fields["expires_at"] = json.RawMessage(
			strconv.FormatInt(expiresAt, 10))
	}

	return renderLocator(fields)
}

func Trimmed(raw json.RawMessage, size int) (json.RawMessage, error) {
	fields, err := locatorFields(raw)
	if err != nil {
		return nil, err
	}

	fields["truncated"] = json.RawMessage("true")
	fields["complete"] = json.RawMessage("false")
	if size >= 0 {
		fields["size"] = json.RawMessage(strconv.FormatInt(int64(size), 10))
	}

	return renderLocator(fields)
}

func Unreachable(raw json.RawMessage, reason string) (json.RawMessage, error) {
	fields, err := locatorFields(raw)
	if err != nil {
		return nil, err
	}

	for _, name := range locatorAddress {
		delete(fields, name)
	}

	fields["unavailable"] = mustQuote(reason)

	return renderLocator(fields)
}

func locatorFields(raw json.RawMessage) (map[string]json.RawMessage, error) {
	fields := map[string]json.RawMessage{}

	if len(bytes.TrimSpace(raw)) == 0 {
		return fields, nil
	}

	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("audit: locator: %w", err)
	}

	return fields, nil
}

func renderLocator(fields map[string]json.RawMessage) (json.RawMessage, error) {
	rest := make([]string, 0, len(fields))

	for name := range fields {
		if !slices.Contains(locatorOrder, name) {
			rest = append(rest, name)
		}
	}

	slices.Sort(rest)

	var buf bytes.Buffer

	buf.WriteByte('{')

	first := true
	write := func(name string) {
		value, ok := fields[name]
		if !ok {
			return
		}

		if !first {
			buf.WriteByte(',')
		}
		first = false

		buf.WriteString(`"` + name + `":`)
		buf.Write(value)
	}

	for _, name := range locatorOrder {
		write(name)
	}

	for _, name := range rest {
		write(name)
	}

	buf.WriteByte('}')

	return buf.Bytes(), nil
}

func mustQuote(s string) json.RawMessage {
	out, _ := json.Marshal(s)
	return out
}

func SpliceStore(raw, value []byte) ([]byte, error) {
	start, end, err := storeSpan(raw)
	if err != nil {
		return nil, err
	}

	if start < 0 {
		return raw, nil
	}

	out := make([]byte, 0, len(raw)-(end-start)+len(value))
	out = append(out, raw[:start]...)
	out = append(out, value...)
	out = append(out, raw[end:]...)

	return out, nil
}

func storeSpan(raw []byte) (int, int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))

	tok, err := dec.Token()
	if err != nil {
		return 0, 0, err
	}

	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, 0, fmt.Errorf("audit: payload is not a JSON object")
	}

	for {
		tok, err = dec.Token()
		if err == io.EOF {
			return -1, -1, nil
		}
		if err != nil {
			return 0, 0, err
		}

		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return -1, -1, nil
		}

		key, ok := tok.(string)
		if !ok {
			return 0, 0, fmt.Errorf("audit: object key is not a string")
		}

		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return 0, 0, err
		}

		if key != "store" {
			continue
		}

		end := int(dec.InputOffset())

		return end - len(value), end, nil
	}
}
