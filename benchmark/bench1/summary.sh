#!/bin/bash
# tools/bench/summarize.sh
# 从原始结果中提取 QPS 和延迟，计算中位数
#
# 用法: cd tools/bench && bash summarize.sh

RESULTS_DIR="./bench_results"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          Benchmark Summary (Median)                         ║"
echo "╠═══════════════════╦════════╦═══════════╦═══════════╦═══════════╦════════════╣"
echo "║ Config            ║ Conc   ║ QPS       ║ P50       ║ P95       ║ P99        ║"
echo "╠═══════════════════╬════════╬═══════════╬═══════════╬═══════════╬════════════╣"

for file in "$RESULTS_DIR"/*.txt; do
    [ -f "$file" ] || continue

    filename=$(basename "$file" .txt)

    # 从文件名解析: A0_baseline_c10_get.txt
    name=$(echo "$filename" | sed 's/_c[0-9]*_.*$//')
    conc=$(echo "$filename" | grep -oP 'c\K[0-9]+')
    req=$(echo "$filename" | grep -oP '(get|set)$')

    # 提取所有 QPS 值，排序取中位数
    qps_values=$(grep -oP 'QPS:\s+\K[0-9.]+' "$file")
    if [ -z "$qps_values" ]; then
        continue
    fi
    qps_median=$(echo "$qps_values" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')

    # 提取 P50 延迟
    p50_values=$(grep -oP 'Latency P50:\s+\K[0-9.]+[µm]s' "$file" | sed 's/µs//;s/ms/*1000/' | bc 2>/dev/null || echo "0")
    p50_median=$(echo "$p50_values" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')

    # 提取 P95 延迟
    p95_values=$(grep -oP 'Latency P95:\s+\K[0-9.]+[µm]s' "$file" | sed 's/µs//;s/ms/*1000/' | bc 2>/dev/null || echo "0")
    p95_median=$(echo "$p95_values" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')

    # 提取 P99 延迟
    p99_values=$(grep -oP 'Latency P99:\s+\K[0-9.]+[µm]s' "$file" | sed 's/µs//;s/ms/*1000/' | bc 2>/dev/null || echo "0")
    p99_median=$(echo "$p99_values" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')

    printf "║ %-17s ║ %-6s ║ %-9.0f ║ %-9s ║ %-9s ║ %-10s ║\n" \
        "${name}_${req}" "$conc" "$qps_median" "${p50_median}µs" "${p95_median}µs" "${p99_median}µs"
done

echo "╚═══════════════════╩══════════╩═══════════╩═══════════╩═══════════╩════════════╝"