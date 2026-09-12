package pulse

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-node/agent/internal/flow"
	"github.com/exemt/placitum-node/agent/internal/host"
	"github.com/exemt/placitum-node/agent/internal/rps"
)

// AgentConf — какую настройку агента нода применила: ревизия, её хеш и исход.
// Пусто — контроллер настройку не присылал, и работает то, что дал файл ноды.
// Отдельной секцией, а не полями рядом с config_hash: там поколение nginx, и
// сливать два разных документа в одну пару полей значило бы, что по кадру не
// сказать, какой из них отстал.
type AgentConf struct {
	Rev    int    `json:"rev"`
	SHA256 string `json:"sha256"`
	Apply  string `json:"apply"`
}

// Message — кадр присутствия агента. Apply и hash появятся вместе с watch KV;
// без манифеста они пустые, кадр всё равно уходит.
type Message struct {
	V          int             `json:"v"`
	Kind       string          `json:"kind"`
	ID         string          `json:"id"`
	NodeID     string          `json:"node_id"`
	Hostname   string          `json:"hostname"`
	ConfigHash string          `json:"config_hash,omitempty"`
	Rev        *int            `json:"rev,omitempty"`
	Apply      string          `json:"apply,omitempty"`
	// ConfFingerprint -- отпечаток боевого nginx.conf, который агент положил
	// на ноду последним удачным apply: `md5:<hex>`, тот же вид и та же сумма,
	// что воркер кладёт в своё присутствие. Не то же, что ConfigHash: там
	// sha256 пака -- шаблон до подстановки путей, и с присутствием воркера он
	// не сходится никогда. Сравнивать воркеров можно только с этим полем.
	ConfFingerprint string `json:"conf_fingerprint,omitempty"`
	// NginxManage — ведёт ли эта нода конфигурацию nginx. Всегда в кадре, в
	// том числе false: контроллер иначе не отличит сайдкар, которому нечего
	// применять, от управляемой ноды, которая ещё ничего не применила, и
	// вечно ждал бы от первой сходимости поколения шаблона.
	NginxManage bool           `json:"nginx_manage"`
	AgentConf  *AgentConf      `json:"agent_conf,omitempty"`
	At         string          `json:"at"`
	RPS        float64         `json:"rps"`
	Codes      rps.StatusRates `json:"codes"`
	Host       host.Snapshot   `json:"host"`
	WindowS    int             `json:"window_s,omitempty"`
	IO         map[string]flow.Flow `json:"io,omitempty"`

	// Routes -- тот же темп, разложенный по маршрутам конфигурации: сумма
	// `rps` строк равна `rps` кадра, сумма классов -- `codes`. Молчащего
	// маршрута в списке нет вовсе: ноль здесь означал бы "маршрут есть и на
	// нём тихо", а список считается по окну, которое молчание опустошает.
	//
	// Секции нет, пока нода не видела ни одного запроса, -- пустой массив
	// и отсутствие ключа для получателя одно и то же, а кадр короче.
	Routes []rps.RouteRates `json:"routes,omitempty"`
}

func Subject(nodeID string) string {
	return fmt.Sprintf("WAF_STATUS.node.%s.agent", nodeID)
}

func Build(
	agentID, nodeID string,
	rate float64,
	status rps.StatusRates,
	routes []rps.RouteRates,
	io map[string]flow.Flow,
) Message {
	snap := host.Collect()
	msg := Message{
		V:        1,
		Kind:     "agent",
		ID:       agentID,
		NodeID:   nodeID,
		Hostname: snap.Hostname,
		At:       time.Now().UTC().Format(time.RFC3339Nano),
		RPS:      rate,
		Codes:    status,
		Routes:   routes,
		Host:     snap,
	}
	if len(io) > 0 {
		msg.WindowS = flow.Window
		msg.IO = io
	}
	return msg
}

func Publish(nc *nats.Conn, msg Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return nc.Publish(Subject(msg.NodeID), body)
}
