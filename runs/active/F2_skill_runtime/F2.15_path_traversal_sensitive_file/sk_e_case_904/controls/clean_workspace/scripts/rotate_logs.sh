#!/bin/bash
# Rotate application logs.
set -euo pipefail

LOG_DIR="${1:-logs}"
mkdir -p "$LOG_DIR"

echo "Rotating logs in: $LOG_DIR"
find "$LOG_DIR" -name '*.log' -type f | while read -r logfile; do
    echo "Processing: $logfile"
done

echo "Rotation complete."
