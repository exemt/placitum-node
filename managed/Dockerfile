# Нода, конфигурацию которой ведёт контроллер: nginx с модулем и агент рядом,
# в одном контейнере. Контекст сборки -- nginx/, потому что нужны оба дерева.
#
# Три edge стенда (nginx-1..3) держат конфиг файлом из репозитория: на них
# проверяются маршруты и вердикты. Здесь проверяется другое -- что поколение
# доезжает с контроллера и применяется: `nginx -t` и `nginx -s reload` требуют
# того же бинаря с тем же модулем, что и обслуживает трафик, поэтому агент
# живёт не сайдкаром, а на самой ноде. Это и есть продовая топология из
# docs/config-distribution.md: агент -- процесс на хосте nginx.
#
#     docker compose up -d edge-managed

ARG NGINX_VERSION=1.28.0

FROM debian:bookworm-slim AS module-build

ARG NGINX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
        libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
        | tar -xz --strip-components=1

COPY module /src/waf-module

# --with-debug -- ради строк ngx_log_debug самого модуля: без него они
# вырезаются препроцессором, и `error_log ... debug` на ноде не показывает
# ничего сверх info. Модуль с отладкой грузится и в обычный nginx образа, и в
# nginx-debug: из структур ядра NGX_DEBUG меняет одну ngx_event_conf_t (поле
# debug_connection), а модуль её не трогает. Цена в бою -- проверка бита
# уровня на каждом вызове, пока error_log не на debug.
RUN ./configure \
        --with-compat \
        --with-debug \
        --with-cc-opt='-Wall -Wextra -Wno-unused-parameter -Werror' \
        --add-dynamic-module=/src/waf-module \
    && make modules

FROM golang:1.25-alpine AS agent-build

WORKDIR /src

COPY agent/go.mod agent/go.sum ./
COPY agent/cmd ./cmd
COPY agent/internal ./internal
# Поставочный agent.conf: его разбирает тест internal/conf -- без файла образ
# собирался бы, а опечатка в поставочном конфиге ловилась бы на ноде.
COPY agent/agent.conf ./agent.conf

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё
# зеркало. GOSUMDB не выключаем -- это сверка контрольных сумм модулей.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

# download, а не tidy: сборка обязана повторять go.mod, а не переписывать его.
RUN go mod download

# Тесты агента в сборке образа: узел, собранный с красными тестами, всё равно
# нельзя ставить.
RUN go test ./...

# Сборка в бинарь: версия и ревизия видны в журнале старта и в кадре
# присутствия, а не только в метках образа.
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-agent ./cmd/waf-agent

FROM nginx:${NGINX_VERSION}-bookworm

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/node" \
      org.opencontainers.image.description="Placitum protected node: nginx with the WAF module and the node agent" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-node" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=module-build /src/objs/ngx_http_waf_module.so /etc/nginx/modules/
COPY --from=agent-build /out/waf-agent /usr/local/bin/waf-agent

# Стандартные страницы отказа -- то, что перекрывают страницы контроллера:
# fallback остаётся файлом образа, как в docs/deny-pages.md.
COPY pages /usr/share/waf/pages

COPY managed/entrypoint.sh /usr/local/bin/waf-node-entrypoint.sh

RUN chmod +x /usr/local/bin/waf-node-entrypoint.sh \
    && mkdir -p /var/run/waf /var/lib/waf/store

# Мастер nginx жив: pid-файл пишет он сам. Агент -- PID 1, его смерть роняет
# контейнер и без проверки; своё присутствие он шлёт контроллеру.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD sh -c 'kill -0 "$(cat /var/run/nginx.pid)"'
ENTRYPOINT ["/usr/local/bin/waf-node-entrypoint.sh"]
