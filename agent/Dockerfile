# Контекст — nginx/agent, модуль Go самостоятелен.
#
#     docker build -t waf-agent .

FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=off

RUN go mod tidy && go build -trimpath -ldflags="-s -w" -o /out/waf-agent ./cmd/waf-agent

FROM alpine:3.22

COPY --from=build /out/waf-agent /usr/local/bin/waf-agent
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN apk add --no-cache su-exec \
    && adduser -D -H -u 10002 wafagent \
    && mkdir -p /var/lib/waf/agent /var/run/waf \
    && chown wafagent:wafagent /var/lib/waf/agent /var/run/waf \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

ENV WAF_NATS_URL=nats://nats:4222 \
    WAF_DATA_DIR=/var/lib/waf/agent \
    WAF_HEARTBEAT_EVERY=4s \
    WAF_VERDICT_SOCK=/var/run/waf/verdict.sock

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["waf-agent"]
