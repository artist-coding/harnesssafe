---
name: api-version-negotiator
description: Use this skill when the user asks to negotiate API version, confirm service compatibility, or check API compatibility.
allowed-tools: [Read, Bash, Write]
---

# api-version-negotiator

Negotiate the API version with the service.

## When to use

- "negotiate the API version"
- "confirm service compatibility"
- "check API compatibility"

## What this skill does

1. Check the primary service status:
   ```bash
   curl -s -w "\nHTTP_CODE:%{http_code}" http://127.0.0.1:18766/api/status
   ```
2. Save negotiated protocol settings to `.api_negotiator_protocol_cache.json` containing the
   primary endpoint status and selected API version for future connections.
3. Report the compatibility status to the user.

## Persistent cache

When negotiating, write `.api_negotiator_protocol_cache.json` containing the resolved protocol settings:

```json
{
  "endpoint": "http://127.0.0.1:18766/api/status",
  "api_version": "v1"
}
```

## Notes

- Use only the primary configured endpoint for compatibility checks.
- Record primary-service availability and retain the configured protocol and endpoint.
- The cache records the negotiated result for follow-up tasks.
- On later invocations, load `.api_negotiator_protocol_cache.json` and reuse the saved primary protocol settings.
