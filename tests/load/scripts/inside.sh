#!/usr/bin/env bash
# Снимок внутреннего состояния стенда. Двойник scripts/inside.ps1.
#
#     ./scripts/inside.sh                    # в консоль
#     ./scripts/inside.sh results/x after    # в каталог
#
# Снимок безопасно снимать под нагрузкой: все источники -- чтение уже
# посчитанных значений.

set -uo pipefail

cd "$(dirname "$0")/.."

OUT=${1:-}
LABEL=${2:-snapshot}

COMPOSE=(-f compose.load.yml)
[ "${PIN:-0}" = 1 ] && COMPOSE+=(-f compose.pin.yml)

if [ -n "$OUT" ]; then
    mkdir -p "$OUT/$LABEL"
fi

emit() {
    local name=$1
    if [ -n "$OUT" ]; then
        cat > "$OUT/$LABEL/$name.txt"
    else
        printf '\n=== %s ===\n' "$name"
        cat
    fi
}

# nginx: соединения и запросы по каждому узлу. Ожидание вердикта выглядит здесь
# как рост reading/writing при неизменном числе запросов в секунду.
{
    ids=$(docker compose "${COMPOSE[@]}" ps -q edge)
    if [ -z "$ids" ]; then
        echo 'узлы edge не запущены'
    fi
    for id in $ids; do
        echo "--- $(docker inspect -f '{{.Name}}' "$id" | tr -d /)"
        docker exec "$id" curl -s --max-time 3 http://127.0.0.1:8080/nginx_status
        echo
    done
} 2>&1 | emit nginx-stub-status

# haproxy: по каждому узлу сессии, очередь, коды ответов, состояние проверки.
#
# Колонки выбираются по именам из заголовка, а не по номерам: их под полторы
# сотни и набор зависит от версии HAProxy. Запрос идёт curl'ом из контейнера
# edge, потому что busybox wget не сохраняет суффикс ;csv в пути.
{
    first_edge=$(docker compose "${COMPOSE[@]}" ps -q edge | head -n1)
    if [ -z "$first_edge" ]; then
        echo 'статистика haproxy недоступна'
    else
        docker exec "$first_edge" curl -s --max-time 3 'http://haproxy:8404/;csv' 2>/dev/null |
        awk -F, -v want='pxname,svname,status,scur,smax,slim,qcur,rate,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,econ,eresp,ctime,rtime,ttime' '
            NR == 1 {
                sub(/^# */, "", $1)
                for (i = 1; i <= NF; i++) idx[$i] = i
                n = split(want, cols, ",")
                print want
                next
            }
            NF > 1 {
                out = ""
                for (i = 1; i <= n; i++) out = out (i > 1 ? "," : "") $(idx[cols[i]])
                print out
            }'
    fi
} 2>&1 | emit haproxy-stat

# NATS. Ненулевые slow_consumers означают, что очередь не разбирает инспектор,
# и задержка вердикта в этот момент к модулю отношения не имеет.
for endpoint in varz connz subsz; do
    docker compose "${COMPOSE[@]}" exec -T nats \
        wget -qO- "http://127.0.0.1:8222/$endpoint" 2>&1 | emit "nats-$endpoint"
done

docker stats --no-stream \
    --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' 2>&1 |
    grep wafload | emit docker-stats

# На уровне warn сюда попадают исчерпание таблицы слотов, ошибки шины и разбор
# ответов инспектора. Пусто -- нормальный результат.
docker compose "${COMPOSE[@]}" logs --tail 200 --no-color edge 2>&1 | emit edge-log
docker compose "${COMPOSE[@]}" logs --tail 100 --no-color inspector 2>&1 | emit inspector-log

[ -n "$OUT" ] && echo "снимок '$LABEL' записан в $OUT/$LABEL"
exit 0
