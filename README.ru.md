# Placitum node

[English](README.md) · Русский

Узел защиты Placitum: nginx с модулем `ngx_http_waf_module` и агент ноды в одном образе.

Модуль принимает трафик и согласует решение по каждому запросу и ответу с внешними инспекторами
через шину сообщений. Агент рядом применяет конфигурацию и отправляет аудит, архив, журнал и
присутствие узла. Логики детекта здесь нет: она в инспекторах — отдельных процессах, которые
пишутся на любом языке.

```
клиент ──► nginx + ngx_http_waf_module ──► приложение
               │  волны инспекторов по шине (NATS)
               │  тело, заголовки и строка запроса — в буфер по локатору
               ▼
            агент ноды ──► аудит и журнал на шину, архив в S3,
                           конфигурация из KV, присутствие на WAF_STATUS
```

## Что здесь лежит

| Каталог | Что это |
| --- | --- |
| `module/` | модуль: исходники на C, `config` для сборки nginx, `Dockerfile` для одного модуля |
| `agent/` | агент ноды на Go и образцовый `agent.conf` |
| `managed/` | образ узла: nginx, модуль, агент и точка входа |
| `pages/` | страницы блокировки из образа; страницы контроллера их перекрывают |

## Как проходит запрос

1. `waf_inspect` на маршруте называет инспекторов и их волны. Инспекторов одной волны спрашивают
   параллельно; следующая волна начинается после предыдущей и видит её ответы.
2. То, что нужно инспекторам (`waf_capture`: заголовки, строка запроса, тело), ложится в буфер
   (Redis), а сообщение несёт локатор вместо самих байтов.
3. Инспектор отвечает `allow`, `score`, `redirect`, `deny` или `error` и может приложить
   сигналы соседям. `deny` или сумма счёта, дошедшая до `waf_score_deny`, заканчивает фазу
   ответом блокировки.
4. Если инспектор опоздал или молчит либо шина лежит, решают `waf_deadline` и `waf_exception`:
   пропустить или заблокировать — по фазе и по причине.
5. Итог уходит агенту по unix-сокету (`waf_agent_socket`); агент публикует событие и
   архивирует удержанные объекты в S3.

Та же модель работает на фазе ответа (`waf_hold response gate`) и на кадрах WebSocket
(`waf_inspect frame`). До шины стоит локальный слой в разделяемой памяти: ограничения частоты
(`waf_local_rate`), наборы данных, синхронные с шиной (`waf_local_dataset`), и circuit breaker.

## Конфигурация

На управляемом узле конфигурацию пишет контроллер. Здесь видно, из чего она состоит:

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

    waf_deny_response blocked status=403;
    waf_deny_response_default blocked;

    waf_capture request headers=64k args=64k;
    waf_deadline request 50ms;
    waf_exception request timeout deny response=blocked;
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

Инспекторы без `waf_bus` не загружаются вовсе: такая конфигурация выглядела бы защищающей, а
отправляла бы каждый запрос в `waf_exception … bus`.

## Страницы блокировки

В `pages/` лежат страницы из образа: `blocked`, `too_many`, `ratelimited`, `captcha_required`,
`auth_required`, `suspicious`, `malformed` и `error`, каждая в HTML и JSON. Их заполняет SSI
из переменных модуля: `$waf_deny_status`, `$waf_deny_scope` и `$waf_deny_subject` (что закрыто:
адрес, сеть, страна, система, сессия или сам запрос), `$waf_deny_retry`, `$waf_deny_ray` (Event ID) и
`$waf_deny_addr`.

## Сборка

```sh
docker build -f managed/Dockerfile -t placitum/node .
docker build -f module/Dockerfile --target artifact --output type=local,dest=./out module
```

`NGINX_VERSION` (по умолчанию 1.28.0) общая для сборки модуля и базового образа. Сборка сверяет
исходники nginx с `NGINX_SHA256`, поэтому для новой версии меняют оба значения. Модуль, собранный
под другую версию, nginx не загрузит. Для своего nginx модуль собирают против той же версии с
`--with-compat` и `--with-http_ssl_module`: без модуля SSL он не сообщит о HTTPS и TLS.

Что нужно узлу, настройки агента и проверка — в [INSTALL.ru.md](INSTALL.ru.md).

## Лицензия

[Apache License 2.0](LICENSE), уведомление об авторстве — в [NOTICE](NOTICE). Репозиторий входит в
открытое ядро Placitum. Инспекторы лицензируются отдельно: в репозитории каждого инспектора лежит
Placitum License Agreement. Выпуски, сделанные до этой смены, выходили на условиях Placitum License
Agreement 1.1.
