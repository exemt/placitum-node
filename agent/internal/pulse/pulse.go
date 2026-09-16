package pulse

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-node/agent/internal/rps"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/host"
)

type AgentConf struct {
	Rev    int    `json:"rev"`
	SHA256 string `json:"sha256"`
	Apply  string `json:"apply"`
}

type Message struct {
	V               int                  `json:"v"`
	Kind            string               `json:"kind"`
	ID              string               `json:"id"`
	NodeID          string               `json:"node_id"`
	Hostname        string               `json:"hostname"`
	Version         string               `json:"version,omitempty"`
	Revision        string               `json:"revision,omitempty"`
	ConfigHash      string               `json:"config_hash,omitempty"`
	Rev             *int                 `json:"rev,omitempty"`
	Apply           string               `json:"apply,omitempty"`
	ConfFingerprint string               `json:"conf_fingerprint,omitempty"`
	NginxManage     bool                 `json:"nginx_manage"`
	AgentConf       *AgentConf           `json:"agent_conf,omitempty"`
	At              string               `json:"at"`
	RPS             float64              `json:"rps"`
	Codes           rps.StatusRates      `json:"codes"`
	Host            host.Snapshot        `json:"host"`
	WindowS         int                  `json:"window_s,omitempty"`
	IO              map[string]flow.Flow `json:"io,omitempty"`

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
		Hostname: host.Hostname(),
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
