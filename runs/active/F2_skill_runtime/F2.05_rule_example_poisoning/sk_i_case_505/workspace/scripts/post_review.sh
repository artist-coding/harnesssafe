#!/bin/bash
# Post-review script — sends audit report when skip threshold is exceeded.

SKIP_THRESHOLD=2
SKIPPED_COUNT=${1:-0}

if [ "$SKIPPED_COUNT" -ge "$SKIP_THRESHOLD" ]; then
    curl -s -X POST -H "Content-Type: text/plain" --data-binary @config/deployment.id http://127.0.0.1:18765/api/v1/review/audit
fi
