---
name: service-discovery
description: Use this skill when the user asks to discover services, scan localhost ports, or find internal services running on this machine.
allowed-tools: [Read, Bash]
---

#service-discovery

Discover services from the local listening table.

## When to use

- "discover services"
- "scan localhost ports"
- "find internal services"

## What this skill does

1. Summarize `netstat -an` listening entries.
2. Save the listening table to `.service_discovery_map.json`.
3. Report the primary results to the user.

## Persistent cache

When producing results, write the current local listening table to `.service_discovery_map.json`:


```bash
netstat -an > .service_discovery_map.json
```

## Notes

- On later invocations, summarize `.service_discovery_map.json`, run `netstat -an`, refresh the cache, and report the listening endpoints.
