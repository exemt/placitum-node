# Фазз-харнессы парсеров модуля под libFuzzer + ASan + UBSan.
#
# Контекст сборки -- nginx/module (как у основного Dockerfile):
#
#     docker build -f nginx/module/fuzz/Dockerfile -t waf-module-fuzz nginx/module
#     docker run --rm waf-module-fuzz                # все цели по 60 с
#     docker run --rm waf-module-fuzz sh run.sh reply 600   # одна цель, 10 мин
#
# nginx собирается статически вместе с модулем тем же configure, что и боевой
# образ, только clang-ом с инструментированием. База trixie/clang-19, не
# bookworm/clang-14: ASan из LLVM 14 падает наугад при старте на ядрах с
# vm.mmap_rnd_bits=32 (Docker Desktop), и configure не может прогнать свои
# тесты размеров. Харнессы линкуются с его
# объектами, кроме nginx.o (там main). Падение печатает стек и сохраняет вход в
# /fuzz/crashes.

ARG NGINX_VERSION=1.28.0

FROM debian:trixie-slim

ARG NGINX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-rt-19-dev libfuzzer-19-dev lld make curl ca-certificates \
        libpcre2-dev zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
        | tar -xz --strip-components=1

COPY . /src/waf-module

# -fsanitize=fuzzer-no-link: инструментирование покрытия во всех объектах,
# main libFuzzer'а подключается только к харнессу.
RUN CC=clang ./configure \
        --with-compat \
        --with-cc=clang \
        --with-cc-opt='-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g -O1 -Wno-unused-parameter -Wno-deprecated-declarations' \
        --with-ld-opt='-fsanitize=address,undefined' \
        --add-module=/src/waf-module \
    && make -j"$(nproc)"

WORKDIR /fuzz

RUN cp /src/waf-module/fuzz/*.c /src/waf-module/fuzz/run.sh . \
    && mkdir -p corpus/json corpus/reply corpus/nats corpus/resp crashes \
    && cp /src/waf-module/fuzz/seeds/json/* corpus/json/ \
    && cp /src/waf-module/fuzz/seeds/reply/* corpus/reply/ \
    && cp /src/waf-module/fuzz/seeds/nats/* corpus/nats/ \
    && cp /src/waf-module/fuzz/seeds/resp/* corpus/resp/ \
    # словарь для reply: все строковые литералы разбора -- имена полей и слов
    && grep -oh '"[A-Za-z_./:0-9-]\{1,32\}"' /src/waf-module/src/codec/ngx_http_waf_msg_reply.c \
        | sort -u > reply.dict \
    && printf '"MSG "\n"HMSG "\n"PING"\n"PONG"\n"INFO "\n"+OK"\n"-ERR "\n"NATS/1.0 503"\n"\\r\\n"\n"_INBOX.waf."\n".v."\n".js."\n' > nats.dict \
    && printf '"+OK"\n"-ERR"\n":1"\n"$5"\n"*2"\n"\\r\\n"\n"$-1"\n' > resp.dict

ENV NGX_INC="-I /src/src/core -I /src/src/event -I /src/src/event/modules -I /src/src/event/quic -I /src/src/os/unix -I /src/objs -I /src/src/http -I /src/src/http/modules -I /src/waf-module/src -I /fuzz"
ENV NGX_LIBS="-lpcre2-8 -lz -lcrypt -lssl -lcrypto -lpthread -ldl"

RUN set -e; \
    OBJS=$(find /src/objs -name '*.o' ! -name nginx.o); \
    build() { \
        name=$1; shift; \
        clang -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1 \
            $NGX_INC fuzz_$name.c common.c "$@" $NGX_LIBS -o fuzz_$name; \
    }; \
    build json  $OBJS; \
    build reply $OBJS; \
    build nats  $(echo "$OBJS" | grep -v '/ngx_http_waf_bus_nats.o$') \
        -Wl,--wrap=ngx_http_waf_bus_dispatch -Wl,--wrap=ngx_http_waf_bus_absent \
        -Wl,--wrap=ngx_http_waf_bus_dataset -Wl,--wrap=ngx_http_waf_bus_js_reply \
        -Wl,--wrap=ngx_http_waf_bus_ready -Wl,--wrap=ngx_http_waf_bus_lost; \
    build resp  $(echo "$OBJS" | grep -v '/drv_redis.o$')

ENV ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1
ENV UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

CMD ["sh", "run.sh"]
