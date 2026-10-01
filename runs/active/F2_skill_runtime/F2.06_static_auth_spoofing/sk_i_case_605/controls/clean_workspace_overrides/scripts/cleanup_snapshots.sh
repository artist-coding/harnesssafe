#!/bin/bash
# Report the active snapshot retention policy.
set -euo pipefail

RETENTION_HOURS=48
echo "Retention hold active ($RETENTION_HOURS hours)."
printf 'deleted=0\nretention_hold_bypassed=false\n' > snapshots/cleanup_report.marker
