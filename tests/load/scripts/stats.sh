#!/usr/bin/env bash
# Выборка CPU и памяти по контейнерам в CSV на всё время прогона. Двойник
# scripts/stats.ps1.
#
# Дублирует cAdvisor намеренно: критерий сценария soak -- «RSS не растёт» --
# нужен независимо от того, заработал ли стек наблюдения.
#
#     ./scripts/stats.sh results/x/stats.csv 5

set -uo pipefail

PATH_OUT=${1:?нужен путь к csv}
INTERVAL=${2:-5}
FILTER=${3:-wafload}

echo 'ts,name,cpu_percent,mem_bytes,mem_percent,net_rx_bytes,net_tx_bytes,pids' > "$PATH_OUT"

to_bytes() {
    awk -v s="$1" 'BEGIN {
        if (match(s, /^[0-9.]+/) == 0) { print 0; exit }
        v = substr(s, RSTART, RLENGTH)
        u = substr(s, RSTART + RLENGTH)
        gsub(/^[ \t]+/, "", u)
        m = 1
        if (u == "kB" || u == "KB") m = 1000
        else if (u == "KiB") m = 1024
        else if (u == "MB") m = 1000000
        else if (u == "MiB") m = 1048576
        else if (u == "GB") m = 1000000000
        else if (u == "GiB") m = 1073741824
        printf "%d", v * m
    }'
}

while true; do
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    docker stats --no-stream \
        --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.PIDs}}' 2>/dev/null |
    grep "$FILTER" |
    while IFS='|' read -r name cpu mem memp net pids; do
        mem_used=$(echo "$mem" | cut -d/ -f1 | xargs)
        rx=$(echo "$net" | cut -d/ -f1 | xargs)
        tx=$(echo "$net" | cut -d/ -f2 | xargs)

        printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$ts" "$name" "${cpu%\%}" "$(to_bytes "$mem_used")" "${memp%\%}" \
            "$(to_bytes "$rx")" "$(to_bytes "$tx")" "$pids" >> "$PATH_OUT"
    done

    sleep "$INTERVAL"
done
