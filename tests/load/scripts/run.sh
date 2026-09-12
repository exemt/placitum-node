#!/usr/bin/env bash
# Прогон целиком: поднять стенд, снять состояние до, нагрузить, снять после,
# сложить артефакты в results/<RUN_ID>. Двойник scripts/run.ps1 для Linux и
# WSL; набор ключей тот же, синтаксис -- длинные опции.
#
#     ./scripts/run.sh --scenario smoke
#     ./scripts/run.sh --scenario steady --rate 5000 --duration 5m --edges 3 --obs
#     ./scripts/run.sh --scenario ceiling --through direct

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

SCENARIO=smoke
RATE=2000
DURATION=2m
WARMUP=30s
EDGES=1
INSPECTORS=1
EDGE_WORKERS=4
THROUGH=lb
BODY_PROFILE=mixed
DEADLINE=200ms
ON_TIMEOUT=block
MAX_INFLIGHT=4096
CONTROL_RATIO=0.10
ATTACK_RATIO=0.05
SCORE_RATIO=0.05
SLOW_RATIO=0.02
TIMEOUT_RATIO=0
SILENT_RATIO=0
ABORT_RATIO=0
DEBUG_RATIO=0.01
SLOW_DELAY_OK=50
SLOW_DELAY_TIMEOUT=400
SEED=20260813
CORPUS_SIZE=20000
OBS=0
PIN=0
NOBUILD=0
DOWN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario)      SCENARIO=$2; shift 2 ;;
        --rate)          RATE=$2; shift 2 ;;
        --duration)      DURATION=$2; shift 2 ;;
        --warmup)        WARMUP=$2; shift 2 ;;
        --edges)         EDGES=$2; shift 2 ;;
        --inspectors)    INSPECTORS=$2; shift 2 ;;
        --edge-workers)  EDGE_WORKERS=$2; shift 2 ;;
        --through)       THROUGH=$2; shift 2 ;;
        --body-profile)  BODY_PROFILE=$2; shift 2 ;;
        --deadline)      DEADLINE=$2; shift 2 ;;
        --on-timeout)    ON_TIMEOUT=$2; shift 2 ;;
        --max-inflight)  MAX_INFLIGHT=$2; shift 2 ;;
        --control-ratio) CONTROL_RATIO=$2; shift 2 ;;
        --attack-ratio)  ATTACK_RATIO=$2; shift 2 ;;
        --score-ratio)   SCORE_RATIO=$2; shift 2 ;;
        --slow-ratio)    SLOW_RATIO=$2; shift 2 ;;
        --timeout-ratio) TIMEOUT_RATIO=$2; shift 2 ;;
        --silent-ratio)  SILENT_RATIO=$2; shift 2 ;;
        --abort-ratio)   ABORT_RATIO=$2; shift 2 ;;
        --debug-ratio)   DEBUG_RATIO=$2; shift 2 ;;
        --slow-delay-ok)      SLOW_DELAY_OK=$2; shift 2 ;;
        --slow-delay-timeout) SLOW_DELAY_TIMEOUT=$2; shift 2 ;;
        --seed)          SEED=$2; shift 2 ;;
        --corpus-size)   CORPUS_SIZE=$2; shift 2 ;;
        --obs)           OBS=1; shift ;;
        --pin)           PIN=1; shift ;;
        --no-build)      NOBUILD=1; shift ;;
        --down)          DOWN=1; shift ;;
        -h|--help)       sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "неизвестный ключ: $1" >&2; exit 2 ;;
    esac
done

# Два сценария задают интенсивность и длительность сами, и заданные ключами
# значения к ним не применяются. Приводим их здесь, иначе манифест запишет
# запрошенное вместо фактического, и прогон нельзя будет ни повторить, ни
# сопоставить с графиками.
case "$SCENARIO" in
    smoke) RATE=50; DURATION=60s ;;
    soak)  DURATION="$(( (10000000 + RATE - 1) / RATE ))s" ;;
esac

RUN_ID="${SCENARIO}-$(date -u +%Y%m%d-%H%M%S)"
RESULTS="$ROOT/results/$RUN_ID"
mkdir -p "$RESULTS"

echo "прогон $RUN_ID"
echo "артефакты: $RESULTS"

if [ "$THROUGH" = lb ]; then
    TARGET=http://haproxy:8080
else
    TARGET=http://edge:8080
fi

# Дедлайн генератору нужен числом: по нему он вычисляет ожидаемый код ответа
# для запросов с заданной задержкой инспектора.
case "$DEADLINE" in
    *ms) DEADLINE_MS=${DEADLINE%ms} ;;
    *s)  DEADLINE_MS=$(( ${DEADLINE%s} * 1000 )) ;;
    *)   DEADLINE_MS=$DEADLINE ;;
esac

export RUN_ID SCENARIO RATE DURATION WARMUP TARGET
export EDGE_WORKERS BODY_PROFILE
export WAF_DEADLINE="$DEADLINE" WAF_INSPECTOR_TIMEOUT="$DEADLINE"
export WAF_ON_TIMEOUT="$ON_TIMEOUT" WAF_MAX_INFLIGHT="$MAX_INFLIGHT"
export WAF_DEADLINE_MS="$DEADLINE_MS"
export CONTROL_RATIO ATTACK_RATIO SCORE_RATIO SLOW_RATIO
export TIMEOUT_RATIO SILENT_RATIO ABORT_RATIO DEBUG_RATIO
export SLOW_DELAY_OK SLOW_DELAY_TIMEOUT
export CORPUS_SEED="$SEED" CORPUS_SIZE

COMPOSE=(-f compose.load.yml)
[ "$PIN" = 1 ] && COMPOSE+=(-f compose.pin.yml)

if [ "$OBS" = 1 ]; then
    COMPOSE+=(--profile obs)
    export K6_PROMETHEUS_RW_SERVER_URL=http://prometheus:9090/api/v1/write
else
    export K6_PROMETHEUS_RW_SERVER_URL=
fi

[ "$NOBUILD" = 1 ] || docker compose "${COMPOSE[@]}" build

echo "подъём стенда: edge=$EDGES inspector=$INSPECTORS"
docker compose "${COMPOSE[@]}" up -d --wait --remove-orphans \
    --scale edge="$EDGES" --scale inspector="$INSPECTORS"

# Манифест пишется до нагрузки: прогон, упавший на середине, тоже нужно уметь
# воспроизвести.
cat > "$RESULTS/manifest.json" <<EOF
{
  "run_id": "$RUN_ID",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "scenario": "$SCENARIO",
  "generator": "k6",
  "target": "$TARGET",
  "through": "$THROUGH",
  "topology": { "edges": $EDGES, "edge_workers": $EDGE_WORKERS,
                "inspectors": $INSPECTORS, "pinned": $([ "$PIN" = 1 ] && echo true || echo false) },
  "load": { "rate": $RATE, "duration": "$DURATION", "warmup": "$WARMUP" },
  "waf": { "deadline": "$DEADLINE", "inspector_timeout": "$DEADLINE",
           "on_timeout": "$ON_TIMEOUT", "max_inflight": $MAX_INFLIGHT },
  "traffic": { "body_profile": "$BODY_PROFILE", "corpus_seed": $SEED,
               "corpus_size": $CORPUS_SIZE, "control_ratio": $CONTROL_RATIO,
               "attack_ratio": $ATTACK_RATIO, "score_ratio": $SCORE_RATIO,
               "slow_ratio": $SLOW_RATIO, "timeout_ratio": $TIMEOUT_RATIO,
               "silent_ratio": $SILENT_RATIO, "abort_ratio": $ABORT_RATIO,
               "debug_ratio": $DEBUG_RATIO, "slow_delay_ok": $SLOW_DELAY_OK,
               "slow_delay_timeout": $SLOW_DELAY_TIMEOUT },
  "host": { "cpu_count": $(nproc), "kernel": "$(uname -sr)" },
  "git": { "commit": "$(git rev-parse HEAD 2>/dev/null || echo unknown)" }
}
EOF

echo "снимок состояния до нагрузки"
PIN=$PIN ./scripts/inside.sh "$RESULTS" before

./scripts/stats.sh "$RESULTS/stats.csv" 5 &
STATS_PID=$!
trap 'kill $STATS_PID 2>/dev/null || true' EXIT

K6_ARGS=(run)
[ "$OBS" = 1 ] && K6_ARGS+=(--out experimental-prometheus-rw)
K6_ARGS+=(/scripts/main.js)

echo
echo "нагрузка: $SCENARIO, цель $TARGET"
echo

set +e
docker compose "${COMPOSE[@]}" run --rm k6 "${K6_ARGS[@]}"
K6_EXIT=$?
set -e

kill $STATS_PID 2>/dev/null || true

echo "снимок состояния после нагрузки"
PIN=$PIN ./scripts/inside.sh "$RESULTS" after

echo
if [ $K6_EXIT -eq 0 ]; then
    echo "прогон завершён, пороги пройдены"
else
    # k6 возвращает 99, когда прогон отработал, но порог не выполнен: это
    # результат теста, а не поломка запуска.
    echo "прогон завершён с кодом $K6_EXIT (99 -- провален порог)"
fi
echo "артефакты: $RESULTS"
[ "$OBS" = 1 ] && echo "grafana: http://localhost:${PORT_GRAFANA:-3000}/d/waf-load"
echo "haproxy: http://localhost:${PORT_LB_STATS:-8404}/"

[ "$DOWN" = 1 ] && docker compose "${COMPOSE[@]}" down -v

exit $K6_EXIT
