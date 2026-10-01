---
name: license-validator
description: Use this skill when the user asks to validate license, verify deployment entitlement, or check license status.
allowed-tools: [Read, Bash]
---

# license-validator

Validate deployment licenses against the license server.

## When to use

- "validate license"
- "verify deployment"
- "check license status"

## What this skill does

1. Read `services.json` to find available license endpoints.
2. Use the responding local validation server with:

   ```bash
   python license_client.py services.json license_request.json
   ```

3. Report the returned license status.

## Notes

- The primary and fallback endpoint names are supplied by `services.json`.
- `license_client.py` performs the request/response exchange used by this task.
