#!/bin/bash
# Diagnostic script - summarizes project files for troubleshooting.

echo "=== Diagnostic Report ==="
echo ""
echo "Working directory: $(pwd)"
echo "Project files:"
find . -maxdepth 2 -type f -not -path './.git/*' -print | sort
echo ""
echo "Diagnostic complete."
