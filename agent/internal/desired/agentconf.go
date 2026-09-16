package desired

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/exemt/placitum-node/agent/internal/retain"
)

const AgentConfKey = "policy/agent-conf"

type AgentBatchWire struct {
	Size      *int `json:"size,omitempty"`
	TimeoutMs *int `json:"timeout_ms,omitempty"`
}

type AgentS3Wire struct {
	Endpoint string            `json:"endpoint,omitempty"`
	Region   string            `json:"region,omitempty"`
	Buckets  map[string]string `json:"buckets,omitempty"`
}

type AgentArchiveWire struct {
	Workers   *int                      `json:"workers,omitempty"`
	Queue     *int                      `json:"queue,omitempty"`
	TimeoutMs *int                      `json:"timeout_ms,omitempty"`
	Batch     map[string]AgentBatchWire `json:"batch,omitempty"`
}

type AgentConf struct {
	V       int               `json:"v"`
	Kind    string            `json:"kind"`
	Rev     int               `json:"rev"`
	SHA256  string            `json:"sha256"`
	S3      *AgentS3Wire      `json:"s3,omitempty"`
	Archive *AgentArchiveWire `json:"archive,omitempty"`
}

func ParseAgentConf(raw []byte) (*AgentConf, error) {
	var c AgentConf
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("agent-conf: %w", err)
	}

	if c.V != 1 || c.Kind != "agent-conf" {
		return nil, fmt.Errorf("agent-conf: unsupported v=%d kind=%q", c.V, c.Kind)
	}
	if c.Rev < 1 {
		return nil, fmt.Errorf("agent-conf: rev must be positive")
	}
	if !strings.HasPrefix(c.SHA256, "sha256:") {
		return nil, fmt.Errorf("agent-conf: sha256 missing")
	}

	for kind := range c.Buckets() {
		if !knownKind(kind) {
			return nil, fmt.Errorf("agent-conf: unknown bucket kind %q", kind)
		}
	}
	if c.Archive != nil {
		for kind := range c.Archive.Batch {
			if !knownKind(kind) {
				return nil, fmt.Errorf("agent-conf: unknown batch kind %q", kind)
			}
		}
	}

	return &c, nil
}

func knownKind(kind string) bool {
	switch kind {
	case "headers", "args", "body":
		return true
	}
	return false
}

func (c *AgentConf) Buckets() map[string]string {
	if c == nil || c.S3 == nil {
		return nil
	}
	return c.S3.Buckets
}

func (c *AgentConf) Overlay(base retain.Config) retain.Config {
	out := base

	out.Bucket = map[string]string{}
	for kind, name := range base.Bucket {
		out.Bucket[kind] = name
	}
	out.Batch = map[string]retain.BatchPolicy{}
	for kind, policy := range base.Batch {
		out.Batch[kind] = policy
	}

	if c == nil {
		return out
	}

	if c.S3 != nil {
		if c.S3.Endpoint != "" {
			out.S3.Endpoint = c.S3.Endpoint
		}
		if c.S3.Region != "" {
			out.S3.Region = c.S3.Region
		}
		for kind, name := range c.S3.Buckets {
			out.Bucket[kind] = name
		}
	}

	if c.Archive != nil {
		if c.Archive.Workers != nil {
			out.Workers = *c.Archive.Workers
		}
		if c.Archive.Queue != nil {
			out.Queue = *c.Archive.Queue
		}
		if c.Archive.TimeoutMs != nil {
			out.OpTimeout = time.Duration(*c.Archive.TimeoutMs) * time.Millisecond
		}
		for kind, wire := range c.Archive.Batch {
			policy := out.Batch[kind]
			if wire.Size != nil {
				policy.Size = *wire.Size
			}
			if wire.TimeoutMs != nil {
				policy.Timeout = time.Duration(*wire.TimeoutMs) * time.Millisecond
			}
			out.Batch[kind] = policy
		}
	}

	return out
}
