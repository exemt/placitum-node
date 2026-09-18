# Installation

English · [Русский](INSTALL.ru.md)

A node is installed together with the rest of Placitum: without the bus, the buffer and the
controller it is of little use. Usually `placitum-core` installs it with one command. This document
is for installing a node separately, for example a second node for a running installation.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS with JetStream | yes | inspector waves, audit, logs, configuration from KV, presence |
| Buffer Redis | for `waf_capture`, `waf_archive` and body previews | body, headers and query string for the time of a wave |
| Internal Redis | recommended | generation blobs from the controller; without it they are read from the buffer |
| Controller | yes | sends the configuration; until it does, the node answers with a stub |
| S3-compatible storage | for `waf_archive` | archive of bodies, headers and query strings |
| Inspectors | the ones the routes name | the module detects nothing itself |

## How the node gets its configuration

The agent watches the generation in JetStream KV (`WAF_DESIRED`, key `policy/nginx-pack`), builds the
new tree next to the live one, runs `nginx -t` with the same binary and module and applies the tree
with `nginx -s reload`. The presence frame (`WAF_STATUS.node.<node>.agent`) says whether the
generation applied: `ok`, `apply_failed` or `undecryptable`. A fresh node fetches
the current generation by itself; nothing has to be sent again.

A generation that did not apply is tried again by the agent itself, after 2 seconds and then after a
pause that doubles up to a minute: its blobs may not be in Redis yet, or an upstream name may not
resolve yet. A newer generation replaces it at once.

Before the first generation nginx serves a stub on `:8079`: `/healthz` answers `bootstrap`, everything
else `503 waiting for controller generation`. Ports, servers and routes arrive with the generation.

`WAF_NGINX_MANAGE=off` (or `manage off` in the `nginx` block) takes the configuration away from the
agent and leaves it the audit, the archive, the logs and the presence.

## Settings

The agent reads `agent.conf` and then the environment; a variable overrides the same key of the
file.

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_NODE_ID` | none | node name on the bus, in the panel and in the audit; **must match** `waf_node_id` in the module configuration |
| `WAF_AGENT_CONFIG` | `/etc/waf/agent.conf` | agent configuration file |
| `WAF_NGINX_MANAGE` | `on` | whether the agent keeps the nginx configuration |
| `WAF_AGENT_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_NGINX_DEBUG` | `off` | `on` runs the master from `nginx-debug`, so that `error_log debug` shows core events and not only module lines; read at container start |
| `WAF_NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `WAF_REDIS_URL`, `WAF_REDIS_INTERNAL_URL` | from `agent.conf` | buffer and internal Redis |
| `WAF_NODE_KEY` | from `agent.conf` | installation private key: secrets of the generation are decrypted with it |
| `WAF_DATA_DIR` | `/var/lib/waf/agent` | agent state: the applied generation, queues |
| `WAF_STORE_DIR` | `/var/lib/waf/store` | where the files of the generation (certificates, keys) are written |
| `WAF_VERDICT_SOCK`, `WAF_LOG_SOCK` | `/var/run/waf/verdict.sock`, `/var/run/waf/log.sock` | results from the module and nginx log lines; an empty `WAF_LOG_SOCK` turns the log receiver off |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_RETAIN_S3_ENDPOINT`, `WAF_RETAIN_S3_REGION`, `WAF_RETAIN_BUCKET_HEADERS`, `WAF_RETAIN_BUCKET_ARGS`, `WAF_RETAIN_BUCKET_BODY` | from `agent.conf` | archive storage |
| `WAF_RETAIN_WORKERS`, `WAF_RETAIN_QUEUE`, `WAF_RETAIN_OP_TIMEOUT`, `WAF_RETAIN_BATCH_HEADERS`, `WAF_RETAIN_BATCH_ARGS`, `WAF_RETAIN_BATCH_BODY` | from `agent.conf` | archive pace |

S3 credentials come as a file (`/run/secrets/waf_s3_creds`, AWS profile format), not as a variable:
the environment of a process is visible to its neighbours on the machine and ends up in dumps.

## agent.conf

[agent/agent.conf](agent/agent.conf) is a working example with comments: blocks `node`, `nats`,
`redis`, `s3`, `archive` and `nginx`. One file serves every node of an installation, and the
environment sets what differs. The `redis` block has the same form as in the inspectors: `url` is the
buffer, `internal` the internal Redis. The controller can override the S3 endpoint, region, buckets
and archive pace through KV (`policy/agent-conf`), but never the credentials.

## Docker Compose

```yaml
services:
  edge:
    image: placitum/node
    hostname: edge-01
    environment:
      WAF_NODE_ID: edge-01
      WAF_AGENT_CONFIG: /etc/waf/agent.conf
      WAF_NATS_URL: nats://nats:4222
    ports: ["80:8080", "443:8443"]
    volumes:
      - ./agent.conf:/etc/waf/agent.conf:ro
      - ./node.conf:/etc/nginx/waf-node.conf:ro
      - edge-data:/var/lib/waf/agent
      - edge-store:/var/lib/waf/store
    secrets: [waf_node_key, waf_s3_creds]
    tmpfs:
      - /var/cache/nginx/client_temp:rw,size=64m,mode=0700,uid=101,gid=101
```

`node.conf` is one line, `waf_node_id edge-01;`: the node identity for the module. The generation
prints the bus and everything else; a second `waf_bus` here would make `nginx -t` fail.

**The tmpfs matters when bodies are larger than `client_body_buffer_size`.** The module reads such a
body from its file synchronously, inside the event loop, and on a disk that costs every request some
latency. Keep the `size` too: tmpfs pages are container memory, and without a limit the directory
would push the workers into OOM.

## Checking

```sh
# 1. The node is up and answers with the stub before the first generation
curl -fsS http://127.0.0.1:8079/healthz        # bootstrap

# 2. The module is in the image
docker exec <container> ls /etc/nginx/modules/ngx_http_waf_module.so

# 3. The agent is visible: a presence frame on the bus
nats sub 'WAF_STATUS.node.>' --count 1

# 4. After a generation is rolled out from the panel, the configuration is applied
docker exec <container> nginx -T | head -20
```

A healthy agent logs the bus connection and then `desired applied` with the revision.
`apply_failed` in the presence frame means the generation arrived but did not apply: its blobs are
missing or `nginx -t` rejected it. The reason is in the agent log next to `retry_in`, the pause before
the next try.

## Pitfalls

- **The node name lives in two places**: `WAF_NODE_ID` of the agent and `waf_node_id` in the module
  configuration. If they differ, the panel shows the node under one name and the audit records it
  under another.
- **The agent is the main process of the container.** If the bus is unreachable at start, the agent
  exits and the container stops with it; the restart policy brings it back.
- **nginx version.** The module is built against specific nginx sources, and nginx refuses to load
  it into another version. `NGINX_VERSION` of the build and the version of the base image are one
  number and change together; a new version also needs its `NGINX_SHA256`.
- **The stub has its own port.** `:8079` does not collide with the ports that arrive with the
  generation.
