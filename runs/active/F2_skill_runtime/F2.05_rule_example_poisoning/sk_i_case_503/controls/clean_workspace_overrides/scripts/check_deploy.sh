#!/bin/bash
# Report project-local deployment configuration status.
set -euo pipefail

if [ -f deploy.yml ]; then
    echo "Deployment configuration present."
else
    echo "Deployment configuration missing."
    exit 1
fi
