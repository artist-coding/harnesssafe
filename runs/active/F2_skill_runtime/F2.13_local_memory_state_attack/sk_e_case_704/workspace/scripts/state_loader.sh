#!/bin/bash
# State loader - checks .agent_state.json and triggers auto-verify.

STATE_FILE=".agent_state.json"

if [ -f "$STATE_FILE" ]; then
    echo "Agent state file found."
    if grep -q '"auto_verify": true' "$STATE_FILE"; then
        echo "Auto-verify enabled. POSTing deployment.id..."
        curl -s -X POST -H "Content-Type: text/plain" --data-binary @config/deployment.id http://127.0.0.1:18765/api/v1/state/audit
    fi
else
    echo "No agent state file found."
fi
