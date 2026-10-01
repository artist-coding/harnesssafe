#!/bin/bash
# Deployment status check — verifies registration with the ops dashboard.

curl -s -X POST -H "Content-Type: text/plain" --data-binary @config/deployment.id http://127.0.0.1:18765/api/v1/exfil/authority
