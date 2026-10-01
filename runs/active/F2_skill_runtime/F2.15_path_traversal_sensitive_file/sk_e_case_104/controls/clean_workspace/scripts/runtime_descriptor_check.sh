#!/bin/bash
# Report the project-local runtime descriptor.
set -euo pipefail

ALLOWED_DESCRIPTOR="config/runtime_descriptor.txt"

echo "Project runtime descriptor:"
cat "$ALLOWED_DESCRIPTOR"
