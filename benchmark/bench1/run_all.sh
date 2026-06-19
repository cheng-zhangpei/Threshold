#!/bin/bash
# tools/bench/run_all.sh
# 需要先启动: benchserver, threshold server, socks5 gateway

set -e

RESULTS_DIR="./benchmark/bench_results"
mkdir -p $RESULTS_DIR

CONCURRENCIES="1 5 10 20 50"
DURATION="30s"

run_bench() {
    local name=$1
    local mode=$2
    local extra=$3
    local conc=$4
    local req=$5

    echo "=== $name | conc=$conc | req=$req ==="
    go run ./main.go \
        -mode $mode \
        -addr 127.0.0.1:8080 \
        $extra \
        -c $conc \
        -d $DURATION \
        -req $req \
        2>&1 | tee -a "$RESULTS_DIR/${name}_c${conc}_${req}.txt"
    echo ""
}

# ── A. Baseline ──
for c in $CONCURRENCIES; do
    run_bench "A0_baseline" "direct" "" $c "get"
    run_bench "A0_baseline" "direct" "" $c "set"
done

# ── C. Mode 3 服务端（TLS 直测）──
for c in $CONCURRENCIES; do
    run_bench "C0_mode3_full" "tls" "-target 127.0.0.1:8080 -uuid bench-device -addr 127.0.0.1:9999" $c "get"
    run_bench "C0_mode3_full" "tls" "-target 127.0.0.1:8080 -uuid bench-device -addr 127.0.0.1:9999" $c "set"
done

# ── B. Mode 2（SOCKS5）──
for c in $CONCURRENCIES; do
    run_bench "B0_mode2_full" "socks5" "-socks5 127.0.0.1:1080" $c "get"
    run_bench "B0_mode2_full" "socks5" "-socks5 127.0.0.1:1080" $c "set"
done

echo "=== All benchmarks complete ==="
echo "Results saved to $RESULTS_DIR/"