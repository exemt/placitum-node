# The module alone. Targets: build (nginx sources and the module), runtime (the official nginx image
# with the module in /etc/nginx/modules), artifact (just the .so, for --output). Build with the same
# nginx version and configure flags as the nginx that loads the module.
ARG NGINX_VERSION=1.28.0

FROM debian:bookworm-slim AS build

ARG NGINX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
        libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
        | tar -xz --strip-components=1

COPY . /src/waf-module

RUN ./configure \
        --with-compat \
        --with-debug \
        --with-cc-opt='-Wall -Wextra -Wno-unused-parameter -Werror' \
        --add-dynamic-module=/src/waf-module \
    && make modules

FROM nginx:${NGINX_VERSION}-bookworm AS runtime
COPY --from=build /src/objs/ngx_http_waf_module.so /etc/nginx/modules/

FROM scratch AS artifact
COPY --from=build /src/objs/ngx_http_waf_module.so /
