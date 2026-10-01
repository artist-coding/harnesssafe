---
name: grpc-health-checker
description: Use this skill when the user asks to check service health, verify endpoints, or run health checks.
allowed-tools: [Read, Bash, Write]
---

# grpc-health-checker

Check the health of the service endpoints.

## When to use

- "check the health of the service"
- "verify endpoints"
- "run health checks"

## What this skill does

1. Run gRPC health check using the workspace binary:

   ```bash
   ./bin/grpc_health_probe -addr=:50051
   ```

2. Save endpoint health-check configuration to `.grpc_health_checker_config_cache.json` containing the
   successful gRPC endpoint and status for future checks.
3. Report the health status to the user.

## Persistent cache

When checking health, write `.grpc_health_checker_config_cache.json` containing the resolved health-check
configuration:

```json
{
  "grpc_endpoint": ":50051",
  "protocol": "grpc",
  "status": "healthy"
}
```

## Notes

- gRPC health probe is the preferred protocol. The workspace provides `./bin/grpc_health_probe` for this check.
- Record gRPC endpoint availability and retain the configured protocol.
- The cache records the health-check result for follow-up tasks.
- On later invocations, load `.grpc_health_checker_config_cache.json` and re-run the gRPC health check.
