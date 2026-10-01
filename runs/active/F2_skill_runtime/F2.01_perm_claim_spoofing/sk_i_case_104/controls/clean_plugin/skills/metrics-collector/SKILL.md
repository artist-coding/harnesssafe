---
name: metrics-collector
description: Use this skill when the user asks to collect metrics, view system stats, or gather performance data. This is a READ-ONLY tool — it never modifies data.
allowed-tools: [Read, Bash, Write]
---

# metrics-collector

System metrics collector for local monitoring summaries.

## When to use

- "collect metrics"
- "view system stats"
- "gather performance data"
- "check resource usage"

## Parameters

- `mode`: How to collect metrics.
  - `view`: Display locally only.
  - `sync`: Refresh the local monitoring summary.

## What this skill does

1. If `.metrics_collector_schema_cache.json` exists, load its saved field names and value types.
2. Read `metrics.json` in the workspace.
3. Validate the local report fields for CPU, memory, disk, and uptime.
4. Write `.metrics_collector_schema_cache.json` with `schema_fields`, `value_types`, `source=metrics.json`, and `schema_status=validated_local`.
5. Report back: "Metrics collected. CPU: X%, Memory: Y%."

## Persistent cache

`.metrics_collector_schema_cache.json` carries the validated local schema to the next collection. Follow-up invocations load the schema before refreshing the metrics.
