/*
 * Событие kind=request в WAF_AUDIT.
 *
 * Агент решение не выносит и запрос не видит. Датаграмма модуля — это уже
 * готовая запись аудита (docs/messages/agent.schema.ts), поэтому она уходит на
 * шину как есть: агент дописывает только конверт, v и kind.
 *
 * Разбирать её в структуру и собирать заново нельзя — так теряется всё, чего в
 * структуре не оказалось, а схему приходится держать в двух местах сразу. Здесь
 * разбирается ровно то, без чего сообщение не отправить: узел для subject и
 * несколько полей для счётчика трафика.
 */

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	Stream   = "WAF_AUDIT"
	Kind     = "request"
	Version  = 1
	MaxBytes = 256 << 20
	MaxAge   = 24 * time.Hour

	VerdictAllow    = "allow"
	VerdictDeny     = "deny"
	VerdictRedirect = "redirect"

	// PhaseRequest -- фаза запроса. Единственная, которая у запроса бывает
	// ровно один раз: `waf on` входит в неё всегда, а фаза ответа и кадры
	// дают ещё по записи на тот же ray. Счётчики трафика смотрят на неё.
	PhaseRequest = "request"
)

// header — поля датаграммы, которые нужны самому агенту. Всё остальное он
// не толкует: незнакомое поле едет дальше нетронутым.
type header struct {
	Ray     string `json:"ray"`
	Node    string `json:"node"`
	Phase   string `json:"phase"`
	TS      string `json:"ts"`
	Verdict string `json:"verdict"`
	HTTP    struct {
		Status int `json:"status"`
	} `json:"http"`

	// Маршрут, на котором сработала конфигурация. Агент им не распоряжается
	// и в шину его не переписывает -- он нужен счётчику трафика по серверам
	// и путям (`internal/rps`).
	Route struct {
		ServerName string `json:"server_name"`
		Location   string `json:"location"`
		// Uuid пути из waf_route_id. Пусто у модуля без директивы.
		ID string `json:"id"`
	} `json:"route"`

	// Единственное поле обменника, которое агент обязан прочитать всегда:
	// по нему решается, есть ли у этой записи хвост работы. Локаторы
	// разбираются отдельно и только тогда, когда хвост есть, — на быстром
	// пути их разбор ничего бы не дал.
	Store struct {
		Archive map[string]Terms `json:"archive"`
	} `json:"store"`

	// Адрес кадра внутри соединения (phase=frame): все кадры лежат под ray
	// рукопожатия, и без стороны с номером объекты двух кадров легли бы в
	// архив под одним именем.
	Frame struct {
		Direction string `json:"direction"`
		Seq       uint64 `json:"seq"`
	} `json:"frame"`
}

// Decision — одна датаграмма модуля: разобранная шапка и сырое тело.
// Публикуется именно Raw, поля рядом — для маршрутизации и метрик.
type Decision struct {
	Ray     string
	Node    string
	Phase   string
	Verdict string
	Status  int

	// Server и Location -- секция route записи: имя блока `server {}` и имя
	// блока `location {}`, как их напечатал модуль. Не Host и не URI.
	// RouteID -- uuid пути из waf_route_id; по нему панель узнаёт маршрут,
	// не сверяя имена. Пусто, если модуль его не прислал.
	Server   string
	Location string
	RouteID  string

	// TS — время события, как его записал модуль. Нужно архиву: объект
	// раскладывается по дате запроса, а не по дате, когда до него дошли руки.
	TS string

	// FrameDirection и FrameSeq — адрес кадра у записи phase=frame: сторона
	// (c2s|s2c) и номер в своём направлении. Пусто и ноль у остальных фаз.
	FrameDirection string
	FrameSeq       uint64

	// Archive — объекты обменника, которые модуль оставил жить, и условия записи
	// каждого. Непустая карта означает, что владение ими перешло агенту: он
	// перекладывает их в архив, подменяет локаторы и чистит обменник сам. Пусто —
	// публиковать как есть, к обменнику не прикасаясь.
	Archive map[string]Terms

	// Raw — запись аудита, как её собрал модуль. Уходит на шину без изменений,
	// кроме конверта и, если archive непуст, секции store.
	Raw []byte
}

func Subject(node string) string {
	if node == "" {
		node = "unknown"
	}

	return "waf.audit.request." + node
}

func Decode(raw []byte) (Decision, error) {
	var h header

	if err := json.Unmarshal(raw, &h); err != nil {
		return Decision{}, err
	}

	// Копия обязательна: буфер приёма переиспользуется следующей датаграммой,
	// а публикация может пережить возврат из обработчика.
	body := make([]byte, len(raw))
	copy(body, raw)

	return Decision{
		Ray:      h.Ray,
		Node:     h.Node,
		Phase:    h.Phase,
		Verdict:  h.Verdict,
		Status:   h.HTTP.Status,
		Server:   h.Route.ServerName,
		Location: h.Route.Location,
		RouteID:  h.Route.ID,
		TS:       h.TS,
		Archive:  h.Store.Archive,
		Raw:      body,

		FrameDirection: h.Frame.Direction,
		FrameSeq:       h.Frame.Seq,
	}, nil
}

// Envelope дописывает v и kind в начало записи. Вставка перед первым полем, а
// не пересборка объекта: порядок остальных полей и их точное представление —
// это то, что модуль уже записал, и трогать его незачем.
//
// node подставляется, только если модуль его не прислал: имя узла знает и
// агент, а запись без него не склеивается.
func Envelope(raw []byte, node string) ([]byte, error) {
	body := bytes.TrimSpace(raw)

	if len(body) < 2 || body[0] != '{' {
		return nil, fmt.Errorf("audit: payload is not a JSON object")
	}

	prefix := fmt.Sprintf(`{"v":%d,"kind":%q`, Version, Kind)

	if node != "" {
		name, err := json.Marshal(node)
		if err != nil {
			return nil, err
		}

		prefix += `,"node":` + string(name)
	}

	// Пустой объект от модуля не бывает осмысленным, но запятая после него
	// дала бы битый JSON, а чинить его на той стороне некому.
	if bytes.Equal(body, []byte("{}")) {
		return []byte(prefix + "}"), nil
	}

	out := make([]byte, 0, len(prefix)+len(body))
	out = append(out, prefix...)
	out = append(out, ',')
	out = append(out, body[1:]...)

	return out, nil
}

func hasNode(raw []byte) bool {
	var probe struct {
		Node *string `json:"node"`
	}

	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}

	return probe.Node != nil
}

// Ensure создаёт поток, если его ещё нет. Конфиг совпадает с deploy/t/streams.sh.
func Ensure(nc *nats.Conn) error {
	if nc == nil {
		return fmt.Errorf("nats connection is nil")
	}

	js, err := nc.JetStream()
	if err != nil {
		return err
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:       Stream,
		Subjects:   []string{"waf.audit.>"},
		Storage:    nats.FileStorage,
		Retention:  nats.LimitsPolicy,
		MaxAge:     MaxAge,
		MaxBytes:   MaxBytes,
		Discard:    nats.DiscardOld,
		Duplicates: 2 * time.Minute,
	})
	if err == nil || errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}

	return err
}
