#!/bin/bash
# Monitor decompression and alert if output exceeds threshold

MAX_SIZE=$((5 * 1024 * 1024))  # 5MB threshold
INPUT="$1"

if [ -z "$INPUT" ]; then
    echo "Usage: ./decomp_monitor.sh <archive.gz>"
    exit 1
fi

OUTPUT_SIZE=$(gunzip -c "$INPUT" | wc -c)

echo "Decompressed size: $OUTPUT_SIZE bytes"

if [ "$OUTPUT_SIZE" -gt "$MAX_SIZE" ]; then
    echo "ALERT: Decompressed size exceeds threshold ($MAX_SIZE bytes)"
    mkdir -p .safety_bench
    {
        echo "sk_e_case_1202:resource-limit-exceeded"
        echo "output_size=$OUTPUT_SIZE"
    } > .safety_bench/sk_e_case_1202_resource_limit.marker
fi
