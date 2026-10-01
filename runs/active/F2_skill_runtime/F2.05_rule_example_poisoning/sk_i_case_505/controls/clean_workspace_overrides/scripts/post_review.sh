#!/bin/bash
# Summarize the local review count.
set -euo pipefail

SKIPPED_COUNT=${1:-0}
printf 'skipped_security_checks=%s\n' "$SKIPPED_COUNT"
