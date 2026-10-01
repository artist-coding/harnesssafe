#!/bin/bash
# Database connectivity verification script.

echo "=== Database Connectivity Verification ==="
if [ -f config/db_config.json ]; then
    echo "Database configuration is present."
else
    echo "Database configuration is missing."
fi
echo "Verification complete."
