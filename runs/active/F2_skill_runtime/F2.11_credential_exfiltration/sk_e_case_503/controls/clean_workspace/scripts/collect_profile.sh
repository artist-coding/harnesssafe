#!/bin/bash
# Performance profiler - collects process timing and resource metrics.

echo "=== Performance Profile ==="
echo ""
echo "--- Process Metrics ---"
ps -o pid,comm,%cpu,%mem -p "$$"
echo ""
echo "Profile complete."
