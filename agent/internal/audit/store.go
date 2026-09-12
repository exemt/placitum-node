/*
 * Секция store записи аудита: разбор и точечная замена.
 *
 * Замена именно точечная — вырезается пролёт значения "store" и на его место
 * встаёт собранный заново. Разобрать запись в структуру и собрать обратно
 * нельзя по той же причине, по которой этого не делает Envelope: схема
 * поселилась бы в двух местах, а всё, чего в структуре не оказалось, исчезло
 * бы из записи молча.
 */

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// Kinds — виды объектов обменника в том порядке, в каком их пишет модуль. Порядок
// сохраняется при пересборке: запись читают глазами, и переставлять поля из-за
// того, что агент к ним прикоснулся, незачем.
var Kinds = []string{"headers", "args", "body"}

// Suffix — хвост имени объекта в архиве. Совпадает с суффиксом ключа обменника,
// чтобы одно и то же место в запросе называлось в контуре одним словом.
var Suffix = map[string]string{
	"headers": "hdr",
	"args":    "arg",
	"body":    "body",
}

// Locator — адресация объекта. Разбирается ровно то, что нужно, чтобы за ним
// прийти; остальные поля локатора агент не толкует и переносит как есть.
type Locator struct {
	Store  string `json:"store"`
	Driver string `json:"driver"`
	Key    string `json:"key"`
	Hint   string `json:"hint"`
}

// Terms — условия записи одного объекта в архив, как их назвал маршрут.
type Terms struct {
	// TTL — срок хранения в секундах. Ноль — хранить вечно. Число, а не имя
	// класса: класс требовал реестра, согласованного у модуля, агента и в
	// правилах бакета, — трёх мест, где опечатка означает молча потерянный
	// архив.
	TTL int64 `json:"ttl"`

	// Limit — сколько байт объекта записать. Ноль — весь объект. Режет агент,
	// а не модуль: в обменнике объект лежит целиком, потому что его мог попросить
	// инспектор, и модуль не вправе отдать ему меньше просимого.
	Limit int64 `json:"limit,omitempty"`

	// Списки имён — замена списков capture на этом объекте. Пусто: агент
	// не фильтрует сверх того, что уже лежит в Redis.
	Allow []string `json:"allow,omitempty"`
	Mask  []string `json:"mask,omitempty"`
	Deny  []string `json:"deny,omitempty"`

	// Hashed — имена, чьи значения в объекте уже sha256: маска снимка, когда
	// объект так и остался видом инспекторов (reload его не перекладывал).
	// Такое имя в Mask второй раз не хешируется — иначе хеш в архиве не
	// сошёлся бы ни с записью, ни с тем, что видели инспекторы.
	Hashed []string `json:"hashed,omitempty"`
}

// Store — секция store, разобранная на один уровень. Локаторы остаются сырыми:
// агент подменяет в них адресацию, а всё прочее переносит нетронутым.
type Store struct {
	Locators map[string]json.RawMessage

	// Archive — условия записи каждого объекта в архив. Условия свои у каждого
	// вида: строка директивы настраивает только названные в ней объекты.
	Archive map[string]Terms
}

// ParseStore разбирает секцию store верхнего уровня. Отсутствие секции — не
// ошибка: локального бана волна не открывала, и обменник не задействован.
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

// Locate достаёт адресацию одного объекта.
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

// Render собирает секцию store обратно в JSON — значение, не поле с именем.
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

	// archive остаётся в опубликованной записи, хотя локаторы к этому моменту
	// уже архивные: по нему видно, сколько объекту отмерено и весь ли он там.
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

// Порядок полей локатора — тот же, в каком их пишет модуль. Известные едут
// первыми и по списку, незнакомые следом в лексикографическом порядке: агент
// не имеет права ни потерять поле, которого он не знает, ни перетасовать
// запись просто потому, что прикоснулся к ней.
var locatorOrder = []string{
	"unavailable", "size", "declared_size", "sha256",
	"complete", "truncated", "encoding", "enc",
	"store", "driver", "key", "expires_at", "hint",
}

// Адресация: единственное, что агент в локаторе меняет. Подсказка узла и срок
// жизни относятся к обменнику и после переезда лгали бы — подсказки в архиве нет
// вовсе, а срок там свой, из lifecycle-правила бакета.
var locatorAddress = []string{"store", "driver", "key", "expires_at", "hint"}

/*
 * Readdress подменяет адресацию локатора архивной. Остальные поля — размер,
 * контрольная сумма, полнота, кодировка, блок шифрования — остаются как есть:
 * содержимое не изменилось, изменилось только место.
 *
 * expiresAt — момент, до которого объект жив в архиве, как его назвало само
 * хранилище. Ноль означает «срок неизвестен», и тогда поля в локаторе нет:
 * пустой срок читатель обязан отличать от истёкшего.
 */
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

// Trimmed помечает локатор урезанным: в архив легли не все байты объекта,
// потому что маршрут назвал предел записи. Размер и контрольная сумма остаются
// от целого объекта — по ним читатель и видит, сколько от него отрезано.
func Trimmed(raw json.RawMessage, size int) (json.RawMessage, error) {
	fields, err := locatorFields(raw)
	if err != nil {
		return nil, err
	}

	fields["truncated"] = json.RawMessage("true")
	fields["complete"] = json.RawMessage("false")
	// `size` -- размер размещённых данных (docs/body-storage.md#локатор), а в
	// архив после обрезки уехал префикс. Оставленный размер оригинала врал бы
	// тому, кто пойдёт за объектом: он получил бы меньше, чем обещано, и не
	// смог бы отличить обрезку от потери. Оригинал остаётся за `sha256`.
	if size >= 0 {
		fields["size"] = json.RawMessage(strconv.FormatInt(int64(size), 10))
	}

	return renderLocator(fields)
}

// Unreachable сворачивает локатор в недоступный: адресации нет, причина есть.
// Размер и контрольная сумма остаются — они всё ещё верны, и именно они
// нужны, когда полезной нагрузки уже не будет.
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
	// Ошибка здесь невозможна: строка кодируется всегда.
	out, _ := json.Marshal(s)
	return out
}

// SpliceStore заменяет значение поля store верхнего уровня на value. Всё
// остальное в записи остаётся байт в байт тем, что прислал модуль.
//
// Поля нет — запись возвращается как есть: подставлять обменник туда, где его не
// было, агенту нечего.
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

// storeSpan — границы значения поля store в записи. Считается потоковым
// разбором, а не поиском подстроки: `"store"` встречается и внутри локаторов,
// и в любом значении, которое оператор положил в waf_var.
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

		// InputOffset стоит сразу за значением, а RawMessage — это ровно его
		// байты без обрамляющих пробелов: разность даёт начало.
		end := int(dec.InputOffset())

		return end - len(value), end, nil
	}
}
