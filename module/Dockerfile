# Сборка модуля против исходников nginx.
#
# Цели:
#   build    -- исходники nginx и собранный модуль
#   runtime  -- официальный образ nginx с модулем в /etc/nginx/modules
#   artifact -- один только .so, для выгрузки через --output
#
# Собирать надо той же версией и с теми же флагами configure, что и целевой
# nginx, иначе модуль даёт порчу памяти, а не ошибку загрузки. Отсюда общий
# NGINX_VERSION у build и runtime: расхождение версий здесь -- это авария в
# продакшене, а не ошибка сборки.

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

# --with-debug -- ради строк ngx_log_debug модуля (см. managed/Dockerfile):
# грузится и в обычный nginx образа, и в nginx-debug.
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
