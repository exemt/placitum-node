package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-node/agent/internal/audit"
	"github.com/exemt/placitum-node/agent/internal/conf"
	"github.com/exemt/placitum-node/agent/internal/desired"
	"github.com/exemt/placitum-node/agent/internal/handoff"
	"github.com/exemt/placitum-node/agent/internal/id"
	"github.com/exemt/placitum-node/agent/internal/nginxlog"
	"github.com/exemt/placitum-node/agent/internal/nodekey"
	"github.com/exemt/placitum-node/agent/internal/pulse"
	"github.com/exemt/placitum-node/agent/internal/retain"
	"github.com/exemt/placitum-node/agent/internal/rps"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-shared/logkit"
	"github.com/exemt/placitum-shared/loglevel"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := conf.Load()
	if err != nil {
		return err
	}

	nodeID := cfg.NodeID
	if nodeID == "" {
		return fmt.Errorf("node.id is required (agent.conf or WAF_NODE_ID)")
	}

	natsURL := cfg.NATS
	dataDir := cfg.DataDir
	sock := cfg.VerdictSock
	logSock := cfg.LogSock
	every := cfg.Heartbeat
	redisURL := cfg.RedisInternalURL
	if redisURL == "" {
		redisURL = cfg.RedisURL
	}
	confDir := cfg.ConfDir
	storeDir := cfg.StoreDir
	nginxBin := cfg.NginxBin

	level, err := loglevel.Env("WAF_AGENT_LOG", "info")
	if err != nil {
		return err
	}

	logIO := flow.New()
	journal := logkit.Open(logkit.Options{
		Service: "agent",
		Writer:  nodeID,
		Level:   level,
		IO:      logIO,
	})
	defer journal.Close()

	log := journal.Log

	log.Info("build", "version", version, "revision", revision)
	slog.SetDefault(log)

	agentID, err := id.Load(dataDir)
	if err != nil {
		return fmt.Errorf("agent id: %w", err)
	}

	var nodeKey *rsa.PrivateKey
	if keyVal := cfg.NodeKey; keyVal != "" {
		key, fp, err := nodekey.Load(keyVal)
		if err != nil {
			return fmt.Errorf("WAF_NODE_KEY: %w", err)
		}
		nodeKey = key
		log.Info("contour key loaded", "fingerprint", fp)
	} else {
		log.Warn("WAF_NODE_KEY is empty; store decrypt will fail")
	}

	nc, err := nats.Connect(natsURL,
		nats.Name("waf-agent-"+nodeID),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info("bus reconnected")
		}),
	)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer nc.Close()

	journal.Attach(context.Background(), nc)
	defer journal.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err)
	} else {
		log.Info("audit stream",
			"stream", audit.Stream,
			"subject", audit.Subject(nodeID),
		)
	}

	if logSock != "" {
		if err := nginxlog.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err)
		} else {
			log.Info("log stream",
				"stream", nginxlog.Stream,
				"subject", nginxlog.Subject(nodeID),
			)
		}
	}

	var applied *desired.Applied
	if redisURL != "" && nodeKey != nil && cfg.NginxManage {
		rdb, err := desired.OpenRedis(redisURL)
		if err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		defer rdb.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		applied, err = desired.Watch(ctx, nc, rdb, nodeKey, desired.Config{
			ConfDir:  confDir,
			StoreDir: storeDir,
			NginxBin: nginxBin,
		}, log)
		if err != nil {
			return fmt.Errorf("desired watch: %w", err)
		}
		log.Info("desired watch started", "kv_key", desired.PackKey, "blobs", desired.RedactURL(redisURL))
	} else {
		applied = desired.NewApplied(confDir)
		if !cfg.NginxManage {
			log.Info("nginx not managed here; config delivery disabled")
		} else if redisURL == "" {
			log.Warn("redis url empty; config delivery disabled")
		}
	}

	traffic := rps.New()
	routes := rps.NewRoutes()
	auditIO := flow.New()

	retainCfg := cfg.Retain

	auditSink := audit.NewSink(nc, nil, log)
	defer auditSink.Close()

	archive := retain.NewSwitch(retainCfg, auditSink.Add, log)

	confCtx, confCancel := context.WithCancel(context.Background())
	defer confCancel()

	agentConf, err := desired.WatchAgentConf(confCtx, nc, func(c *desired.AgentConf) error {
		return archive.Apply(c.Overlay(retainCfg))
	}, log)
	if err != nil {
		log.Warn("agent conf watch failed", "error", err.Error())
		agentConf = &desired.AgentApplied{}
	} else {
		log.Info("agent conf watch started", "kv_key", desired.AgentConfKey)
	}

	if cfg.Path != "" {
		log.Info("config", "file", cfg.Path)
	}

	if live := archive.Config(); live.Enabled() {
		log.Info("archive on",
			"endpoint", live.S3.Endpoint,
			"region", live.S3.Region,
			"workers", live.Workers,
			"queue", live.Queue,
			"batch_headers", batchLog(live.Batch["headers"]),
			"batch_args", batchLog(live.Batch["args"]),
			"batch_body", batchLog(live.Batch["body"]),
		)
	} else {
		log.Info("archive off")
	}

	stopHandoff, err := handoff.Serve(sock, func(raw []byte) {
		d, err := audit.Decode(raw)
		auditIO.Add(uint64(len(raw)), 0, err != nil, 0)
		if err != nil {
			log.Warn("verdict decode failed", "error", err)
			return
		}

		if d.Node == "" {
			d.Node = nodeID
		}

		if d.Phase == "" || d.Phase == audit.PhaseRequest {
			traffic.Add(d.Status, d.Verdict)
			routes.Add(d.Server, d.Location, d.RouteID, d.Status, d.Verdict)
		}

		archive.Handle(d)
	})
	if err != nil {
		return fmt.Errorf("verdict socket: %w", err)
	}

	defer archive.Close()
	defer stopHandoff()

	log.Info("verdict socket", "path", sock)

	var logSink *nginxlog.Sink

	if logSock != "" {
		sink, stopLog, err := nginxlog.Serve(nc, logSock, nodeID, logIO, log)
		if err != nil {
			log.Error("log socket failed", "path", logSock, "error", err.Error())
		} else {
			logSink = sink
			defer stopLog()
			log.Info("log socket", "path", logSock)
		}
	} else {
		log.Info("log socket off")
	}

	nginxManage := cfg.NginxManage

	subject := pulse.Subject(nodeID)
	log.Info("heartbeat on",
		"node_id", nodeID,
		"id", agentID,
		"subject", subject,
		"every", every.String(),
	)

	tick := time.NewTicker(every)
	defer tick.Stop()

	if err := beat(nc, agentID, nodeID, traffic, routes, auditIO, logIO, logSink, auditSink, archive, applied, nginxManage, agentConf, log); err != nil {
		log.Warn("heartbeat failed", "error", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-stop:
			log.Info("shutting down")
			return nil
		case <-tick.C:
			if err := beat(nc, agentID, nodeID, traffic, routes, auditIO, logIO, logSink, auditSink, archive, applied, nginxManage, agentConf, log); err != nil {
				log.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

func beat(
	nc *nats.Conn,
	agentID, nodeID string,
	traffic *rps.Counter,
	routes *rps.Routes,
	auditIO *flow.Counter,
	logIO *flow.Counter,
	logSink *nginxlog.Sink,
	auditSink *audit.Sink,
	archive *retain.Switch,
	applied *desired.Applied,
	nginxManage bool,
	agentConf *desired.AgentApplied,
	log *slog.Logger,
) error {
	io := map[string]flow.Flow{
		"audit":   auditIO.Snapshot(),
		"archive": archive.IO(),
	}

	if logSink != nil {
		io["log"] = logIO.Snapshot()
	}
	msg := pulse.Build(agentID, nodeID, traffic.Rate(), traffic.Status(), routes.Snapshot(), io)
	msg.Version, msg.Revision = version, revision

	msg.NginxManage = nginxManage

	hash, rev, apply, conf := applied.Snapshot()
	if hash != "" {
		msg.ConfigHash = hash
		msg.Apply = apply
		r := rev
		msg.Rev = &r
	}

	msg.ConfFingerprint = conf

	confRev, confHash, confApply := agentConf.Snapshot()
	if confRev > 0 {
		msg.AgentConf = &pulse.AgentConf{
			Rev:    confRev,
			SHA256: confHash,
			Apply:  confApply,
		}
	}

	if err := pulse.Publish(nc, msg); err != nil {
		return err
	}
	log.Debug("heartbeat",
		"hostname", msg.Hostname,
		"rps", msg.RPS,
		"2xx", msg.Codes.XX2,
		"3xx", msg.Codes.XX3,
		"4xx", msg.Codes.XX4,
		"5xx", msg.Codes.XX5,
		"cpu", msg.Host.CPU.Usage,
		"mem_used", msg.Host.Memory.Used,
		"mem_total", msg.Host.Memory.Total,
		"config_hash", hash,
		"conf_fingerprint", conf,
		"apply", apply,
		"agent_conf_rev", confRev,
		"agent_conf_apply", confApply,
		"log_dropped", dropped(logSink),
		"audit_dropped", auditSink.Dropped(),
		"routes", len(msg.Routes),
		"routes_dropped", routes.Dropped(),
	)
	return nil
}

func dropped(sink *nginxlog.Sink) uint64 {
	if sink == nil {
		return 0
	}

	return sink.Dropped()
}

func batchLog(p retain.BatchPolicy) string {
	if p.Size <= 1 && p.Timeout <= 0 {
		return "off"
	}

	out := ""
	if p.Size > 0 {
		out = fmt.Sprintf("size=%d", p.Size)
	}
	if p.Timeout > 0 {
		if out != "" {
			out += " "
		}
		out += "timeout=" + p.Timeout.String()
	}

	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
