/*
 * Агент ноды. Пульс присутствия на WAF_STATUS, публикатор kind=request
 * в WAF_AUDIT, watch KV policy/nginx-pack -> fetch + decrypt + apply.
 */

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
	"github.com/exemt/placitum-node/agent/internal/flow"
	"github.com/exemt/placitum-node/agent/internal/handoff"
	"github.com/exemt/placitum-node/agent/internal/id"
	"github.com/exemt/placitum-node/agent/internal/logkit"
	"github.com/exemt/placitum-node/agent/internal/nginxlog"
	"github.com/exemt/placitum-node/agent/internal/nodekey"
	"github.com/exemt/placitum-node/agent/internal/pulse"
	"github.com/exemt/placitum-node/agent/internal/retain"
	"github.com/exemt/placitum-node/agent/internal/rps"
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
	// Блобы поколения -- из внутреннего Redis контура; без него, как до
	// разделения, из обменника. Архив (retain) в любом случае ходит в обменник.
	redisURL := cfg.RedisInternalURL
	if redisURL == "" {
		redisURL = cfg.RedisURL
	}
	confDir := cfg.ConfDir
	storeDir := cfg.StoreDir
	nginxBin := cfg.NginxBin

	level, err := logkit.Env("WAF_AGENT_LOG", "info")
	if err != nil {
		return err
	}

	/*
	 * Свой журнал агента -- в waf.log рядом со строками nginx этой же ноды
	 * (internal/logkit): writer у обоих -- имя ноды, сервис -- agent и nginx.
	 * Канал log в пульсе общий: потеря строки агента и строки nginx -- одна и
	 * та же поломка шины.
	 */
	logIO := flow.New()
	journal := logkit.Open(logkit.Options{
		Service: "agent",
		Writer:  nodeID,
		Level:   level,
		IO:      logIO,
	})
	defer journal.Close()

	log := journal.Log
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

	// После шины и раньше её закрытия: накопленное добивается, пока она жива.
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

	// Desired config watch
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

	/*
	 * Записи аудита уезжают пачками, а не по одной на запрос: тридцать тысяч
	 * публикаций в секунду с ноды кладут не шину, а потребителя -- вставка в
	 * ClickHouse партией из одного сообщения даёт "too many parts".
	 *
	 * Закрывается последним из всей цепочки: архив на выходе дописывает в него
	 * то, что успел перенести, и пачка обязана пережить его закрытие.
	 */
	auditSink := audit.NewSink(nc, nil, log)
	defer auditSink.Close()

	// Switch, а не Pool: настройка архива приезжает с контроллера и меняется
	// на лету. Перенастройка -- замена пула целиком, см. retain/switch.go.
	archive := retain.NewSwitch(retainCfg, auditSink.Add, log)

	/*
	   Наблюдение за настройкой агента. Не под NginxManage и не под Redis:
	   раскатку nginx ведёт одна нода контура, а архив -- все, и сайдкар,
	   который только возит объекты, обязан получать её настройку тоже.

	   Документ ложится оверлеем на то, что дал файл ноды: реквизиты и адрес
	   обменника контроллер не присылает и прислать не может.
	*/
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

		/*
		 * Счётчики трафика считают запросы, а не записи аудита. У одного
		 * запроса записей бывает несколько: фаза ответа пишет свою поверх
		 * отложенной записи запроса, а кадровый трафик -- по записи на кадр.
		 * Единица "запросов в секунду" есть только у фазы запроса, и она у
		 * запроса ровно одна: `waf on` входит в неё всегда.
		 *
		 * Пустая фаза -- кадр модуля, который её не прислал; такое считаем,
		 * иначе старый модуль обнулил бы метр целиком.
		 */
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

	/*
	 * Второй сокет ноды: строки access_log и error_log, которые nginx кладёт
	 * туда своим syslog-писателем. Пусто — приёмника нет, и это законная
	 * настройка: логи ноды может собирать кто-то другой.
	 *
	 * Отказ сокета логов ноду не валит. Без сокета вердиктов агент бесполезен,
	 * а без этого он по-прежнему ведёт аудит, архив и пульс — падать здесь
	 * значило бы менять потерю журнала на потерю всего остального.
	 */
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

	// Роль ноды едет в каждом кадре, а не выводится контроллером из молчания:
	// «нечего применять» и «ещё не применил» — разные вещи.
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

	// Канал появляется в кадре только там, где сокет логов включён: пустая
	// строка «log 0 ops» на ноде без приёмника выглядела бы как молчащий
	// nginx, а не как отсутствие канала.
	if logSink != nil {
		io["log"] = logIO.Snapshot()
	}
	msg := pulse.Build(agentID, nodeID, traffic.Rate(), traffic.Status(), routes.Snapshot(), io)

	msg.NginxManage = nginxManage

	hash, rev, apply, conf := applied.Snapshot()
	if hash != "" {
		msg.ConfigHash = hash
		msg.Apply = apply
		r := rev
		msg.Rev = &r
	}

	// Отдельно от поколения: отпечаток есть и до первого apply -- на диске
	// лежит конфиг прошлого запуска, и воркеры работают именно по нему.
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
	// Кадр раз в четыре секунды -- ход работы, а не событие: на info он давал
	// бы журналу контура строку в секунду с каждой ноды. Отладке -- он.
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

// dropped — строки лога, выброшенные переполнением буфера. Ноль на ноде без
// приёмника, ноль же на исправной: ненулевое значение в кадре означает, что
// шина не успевала.
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
