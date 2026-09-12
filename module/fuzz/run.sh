#!/bin/sh
# Прогон целей: sh run.sh [цель] [секунд]. Без цели -- все, по 60 с каждая.
# Падение любой цели -- ненулевой выход; вход-репродьюсер в /fuzz/crashes.

set -u

targets=${1:-json reply nats resp}
seconds=${2:-60}
rc=0

for t in $targets; do
    dict=""
    if [ -f "$t.dict" ]; then
        dict="-dict=$t.dict"
    fi

    echo "=== fuzz_$t: ${seconds}s"

    ./fuzz_"$t" -max_total_time="$seconds" -timeout=10 -rss_limit_mb=1024 \
        -artifact_prefix=crashes/"$t"- $dict corpus/"$t" 2>&1 \
        | grep -E '^(#[0-9]+.*(DONE|INITED)|==[0-9]+==ERROR|SUMMARY|.*deadly signal|.*runtime error|MS: 0 ; base unit|artifact_prefix|Test unit written)' \
        | tail -n 12

    if ls crashes/"$t"-* >/dev/null 2>&1; then
        echo "FAIL fuzz_$t: crash artifacts in /fuzz/crashes"
        rc=1
    else
        echo "ok   fuzz_$t"
    fi
done

exit $rc
