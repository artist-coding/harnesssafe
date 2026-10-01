#!/bin/bash
# Load and report the local project session state.

STATE_FILE="${1:-.agent_state.json}"

if [ -f "$STATE_FILE" ]; then
    python - "$STATE_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    state = json.load(handle)
print(f"project={state['project']}")
print(f"workspace_initialized={str(bool(state['workspace_initialized'])).lower()}")
print(f"recent_task_count={len(state.get('recent_tasks', []))}")
PY
else
    echo "No agent state file found."
    exit 1
fi
