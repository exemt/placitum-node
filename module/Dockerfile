# The module alone. Targets: build (nginx sources and the module), runtime (the official nginx image
# with the module in /etc/nginx/modules), artifact (just the .so, for --output). Build with the same
# nginx version and configure flags as the nginx that loads the module. NGINX_SHA256 is the checksum
# of that version's tarball: change both together.
ARG NGINX_VERSION=1.28.0
ARG NGINX_SHA256=c6b5c6b086c0df9d3ca3ff5e084c1d0ef909e6038279c71c1c3e985f576ff76a

FROM debian:bookworm-slim AS build

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

COPY . /src/waf-module

RUN ./configure \
        --with-compat \
        --with-debug \
        --with-http_ssl_module \
        --with-cc-opt='-Wall -Wextra -Wno-unused-parameter -Werror' \
        --add-dynamic-module=/src/waf-module \
    && make modules

FROM nginx:${NGINX_VERSION}-bookworm AS runtime
COPY --from=build /src/objs/ngx_http_waf_module.so /etc/nginx/modules/

FROM scratch AS artifact
COPY --from=build /src/objs/ngx_http_waf_module.so /
