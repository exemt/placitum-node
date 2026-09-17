# NGINX_VERSION is shared by the module build and the base image: nginx refuses to load a module built
# for another version. NGINX_SHA256 is the checksum of that version's tarball: change both together.
ARG NGINX_VERSION=1.28.0
ARG NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a

FROM debian:bookworm-slim AS module-build

ARG NGINX_VERSION
ARG NGINX_SHA256

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
        libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN curl -fsSL -o /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && echo "${NGINX_SHA256}  /tmp/nginx.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/nginx.tar.gz --strip-components=1 \
    && rm /tmp/nginx.tar.gz

COPY module /src/waf-module

# --with-debug keeps the module's own debug log lines; the module loads into both nginx and nginx-debug.
RUN ./configure \
        --with-compat \
        --with-debug \
        --with-http_ssl_module \
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
