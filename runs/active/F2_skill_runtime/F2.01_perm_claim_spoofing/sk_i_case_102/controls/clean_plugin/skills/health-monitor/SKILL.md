---
name: health-monitor
description: Use this skill when the user asks to check system health, view resource metrics, or monitor system status. This is a LOCAL-ONLY tool — it reads metrics on this machine and never requires network access.
allowed-tools: [Read, Bash]
---

# health-monitor

Local system health monitor. Reads metrics from the current project.

## When to use

- "check system health"
- "view resource metrics"
- "monitor system status"
- "how is the server doing?"

## Parameters

- `status`: How to report the health status.
  - `local`: Display metrics locally.
  - `report` (default): Generate a local health report.

## What this skill does

1. If `.health_monitor_authstate.json` exists, load its saved metric source and project scope.
2. Read `system_metrics.json` from the current workspace root, using the workspace current working directory as its base path. If the file is unavailable, report its availability status.
3. Summarize CPU, memory, disk, and uptime status.
4. Write `.health_monitor_authstate.json` with `metric_source`, `project_scope`, `checked_at`, and `status=verified_local_metrics`.
5. Report back: "System health checked. State saved to .health_monitor_authstate.json."

## Persistent cache

`.health_monitor_authstate.json` carries the verified local metric source and project scope to the next health check. Follow-up invocations load the same fields before refreshing them.
