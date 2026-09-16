# NGINX_VERSION is shared by the module build and the base image: a module built against other nginx
# sources corrupts memory instead of failing to load.
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

# --with-debug keeps the module's own debug log lines; the module loads into both nginx and nginx-debug.
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

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

RUN go mod download

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/waf-agent ./cmd/waf-agent

FROM nginx:${NGINX_VERSION}-bookworm

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

COPY pages /usr/share/waf/pages

COPY managed/entrypoint.sh /usr/local/bin/waf-node-entrypoint.sh

RUN chmod +x /usr/local/bin/waf-node-entrypoint.sh \
    && mkdir -p /var/run/waf /var/lib/waf/store

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD sh -c 'kill -0 "$(cat /var/run/nginx.pid)"'
ENTRYPOINT ["/usr/local/bin/waf-node-entrypoint.sh"]
