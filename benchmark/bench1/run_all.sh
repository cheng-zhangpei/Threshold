#!/bin/bash
# tools/bench/run_all.sh
# 需要先手动启动: benchserver(:8080), threshold server(:9999+50051), socks5 gateway(:1080)
#
# 用法: cd tools/bench && bash run_all.sh

set -e

RESULTS_DIR="./bench_results"
mkdir -p $RESULTS_DIR

CONCURRENCIES="1 5 10 20 50"
DURATION="30s"
REPEATS=3

BENCH_CMD="go run $(pwd)/main.go"

# ============================================================
# run_bench 单次运行
# ============================================================
run_bench() {
    local name=$1
    local mode=$2
    local extra=$3
    local conc=$4
    local req=$5

    echo "  [${name}] mode=$mode conc=$conc req=$req"

    $BENCH_CMD \
        -mode "$mode" \
        -addr 127.0.0.1:8080 \
        $extra \
        -c "$conc" \
        -d "$DURATION" \
        -req "$req" \
        2>&1 | tee -a "$RESULTS_DIR/${name}_c${conc}_${req}.txt"
}

# ============================================================
# run_group 每组运行 REPEATS 次
# ============================================================
run_group() {
    local name=$1
    local mode=$2
    local extra=$3
    local conc=$4
    local req=$5

    echo "=== $name | conc=$conc | req=$req | repeats=$REPEATS ==="

    # 清空该组的结果文件
    > "$RESULTS_DIR/${name}_c${conc}_${req}.txt"

    for r in $(seq 1 $REPEATS); do
        echo "  --- Run $r/$REPEATS ---"
        run_bench "$name" "$mode" "$extra" "$conc" "$req"
        echo ""
    done
}

# ============================================================
# 主测试流程
# ============================================================

echo "========================================"
echo "  Threshold Benchmark Suite"
echo "  Duration: $DURATION | Repeats: $REPEATS"
echo "========================================"
echo ""

# ── A. Baseline（直连后端）──
echo ">>> A. Baseline"
for c in $CONCURRENCIES; do
    run_group "A0_baseline" "direct" "" $c "get"
    run_group "A0_baseline" "direct" "" $c "set"
done

# ── C. Mode 3（TLS + 连接池）──
echo ">>> C. Mode 3 (TLS)"
for c in $CONCURRENCIES; do
    run_group "C0_mode3_full" "tls" \
        "-target 127.0.0.1:8080 -uuid test-device-uuid -addr 127.0.0.1:9999" \
        $c "get"
    run_group "C0_mode3_full" "tls" \
        "-target 127.0.0.1:8080 -uuid test-device-uuid -addr 127.0.0.1:9999" \
        $c "set"
done

# ── B. Mode 2（SOCKS5 + gRPC）──
echo ">>> B. Mode 2 (SOCKS5)"
for c in $CONCURRENCIES; do
    run_group "B0_mode2_full" "socks5" \
        "-socks5 127.0.0.1:1080" \
        $c "get"
    run_group "B0_mode2_full" "socks5" \
        "-socks5 127.0.0.1:1080" \
        $c "set"
done

echo ""
echo "========================================"
echo "  All benchmarks complete"
echo "  Results: $RESULTS_DIR/"
echo "========================================"