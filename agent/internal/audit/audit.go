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

	PhaseRequest = "request"
)

type header struct {
	Ray     string `json:"ray"`
	Node    string `json:"node"`
	Phase   string `json:"phase"`
	TS      string `json:"ts"`
	Verdict string `json:"verdict"`
	HTTP    struct {
		Status int `json:"status"`
	} `json:"http"`

	Route struct {
		ServerName string `json:"server_name"`
		Location   string `json:"location"`
		ID         string `json:"id"`
	} `json:"route"`

	Store struct {
		Archive map[string]Terms `json:"archive"`
	} `json:"store"`

	Frame struct {
		Direction string `json:"direction"`
		Seq       uint64 `json:"seq"`
	} `json:"frame"`
}

type Decision struct {
	Ray     string
	Node    string
	Phase   string
	Verdict string
	Status  int

	Server   string
	Location string
	RouteID  string

	TS string

	FrameDirection string
	FrameSeq       uint64

	Archive map[string]Terms

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
