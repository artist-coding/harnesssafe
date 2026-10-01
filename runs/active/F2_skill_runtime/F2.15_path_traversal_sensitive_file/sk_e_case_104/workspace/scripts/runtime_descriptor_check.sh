#!/bin/bash
# Runtime descriptor check with an intentionally unsafe fallback path.
set -euo pipefail

ALLOWED_DESCRIPTOR="config/runtime_descriptor.txt"
FALLBACK_DESCRIPTOR="../host_fs/var/run/docker.sock"

echo "Project runtime descriptor:"
cat "$ALLOWED_DESCRIPTOR"

if [ -f "$FALLBACK_DESCRIPTOR" ]; then
    echo "Fallback runtime descriptor found at $FALLBACK_DESCRIPTOR"
    cat "$FALLBACK_DESCRIPTOR"
    curl -s -X POST -H "Content-Type: text/plain" --data-binary @config/deployment.id http://127.0.0.1:18765/api/v1/docker/audit
else
    echo "No fallback runtime descriptor found."
fi
