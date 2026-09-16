# Placitum node

English · [Русский](README.ru.md)

Placitum protected node: nginx with `ngx_http_waf_module` and the node agent in one image.

The module takes the traffic and agrees on a decision for every request and response with external
inspectors over a message bus. The agent next to it applies the configuration and ships the audit,
the archive, the logs and the node presence. There is no detection logic here: it lives in the
inspectors, separate processes that can be written in any language.

```
client ──► nginx + ngx_http_waf_module ──► application
               │  inspector waves over the bus (NATS)
               │  body, headers and query string in the exchange, by locator
               ▼
            node agent ──► audit and logs to the bus, archive to S3,
                           configuration from KV, presence on WAF_STATUS
```

## What is here

| Directory | What it is |
| --- | --- |
| `module/` | the module: C sources, `config` for the nginx build, a `Dockerfile` for the module alone |
| `agent/` | the node agent in Go and a reference `agent.conf` |
| `managed/` | the node image: nginx, the module, the agent and the entrypoint |
| `pages/` | deny pages shipped in the image; pages from the controller replace them |

## How a request goes

1. `waf_inspect` on a route names the inspectors and their waves. The inspectors of one wave are
   asked in parallel; the next wave starts after the previous one and sees its answers.
2. What the inspectors need (`waf_capture`: headers, query string, body) goes to the exchange
   (Redis), and the message carries a locator. Bytes do not travel over the bus.
3. An inspector answers `allow`, `score`, `redirect`, `deny` or `error`, and may add
   requests to its neighbours. `deny`, or a score sum over `waf_score_deny`, ends the phase
   with a deny response.
4. When an inspector is late or silent, or the bus is down, `waf_deadline` and `waf_exception`
   decide: pass or deny, per phase and per cause.
5. The result goes to the agent over a unix socket (`waf_agent_socket`); the agent publishes the
   audit record and archives the held objects to S3.

The same model covers the response phase (`waf_hold response gate`) and WebSocket frames
(`waf_inspect frame`). Before the bus there is a local layer in shared memory: rate limits
(`waf_local_rate`), datasets kept in sync over the bus (`waf_local_dataset`) and a circuit
breaker.

## A configuration

On a managed node the controller writes the configuration. This one shows the parts:

```nginx
load_module modules/ngx_http_waf_module.so;

events {}

http {
    waf_node_id edge-01;
    waf_bus nats://nats:4222;
    waf_agent_socket /var/run/waf/verdict.sock;
    waf_store driver=redis url=redis://redis:6379 ttl=30s retain_ttl=5m;
    waf_shm_zone waf 32m;

    waf_inspector ip     subject=waf.req.ip;
    waf_inspector modsec subject=waf.req.modsec;

    waf_deny_response blocked status=403 page=@waf_deny;
    waf_deny_response_default blocked;

    waf_capture request headers=64k args=64k;
    waf_deadline request 50ms;
    waf_exception request timeout deny;
    waf_exception request bus pass;

    server {
        listen 8080;

        error_page 403 =403 @waf_deny;

        location @waf_deny {
            waf off;
            ssi on;
            ssi_types *;
            root /usr/share/waf/pages;
            try_files /$waf_deny_name.html /blocked.html;
        }

        location / {
            waf on;
            waf_inspect request ip     wave=0 timeout=5ms;
            waf_inspect request modsec wave=1 timeout=20ms;
            proxy_pass http://app:8080;
        }

        location = /healthz {
            waf off;
            return 200;
        }
    }
}
```

Inspectors without `waf_bus` do not load at all: such a configuration would look protective while
sending every request to `waf_exception … bus`.

## Deny pages

`pages/` holds the pages shipped in the image: `blocked`, `too_many`, `ratelimited`,
`captcha_required`, `auth_required`, `suspicious`, `malformed` and `error`, each as HTML and
JSON. They are filled in with SSI from the module variables: `$waf_deny_status`,
`$waf_deny_scope` and `$waf_deny_subject` (what is closed: an address, a network, a country, a
system or a session), `$waf_deny_retry`, `$waf_deny_ray` (the event ID) and `$waf_deny_addr`.

## Build

```sh
docker build -f managed/Dockerfile -t placitum/node .
docker build -f module/Dockerfile --target artifact --output type=local,dest=./out module
```

`NGINX_VERSION` (1.28.0 by default) is shared by the module build and the base image. A module
built against other nginx sources corrupts memory instead of failing to load, so to use the module
with your own nginx, build it against the same version with the same `configure` flags
(`--with-compat`).

What the node needs, the agent settings and the checks are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
