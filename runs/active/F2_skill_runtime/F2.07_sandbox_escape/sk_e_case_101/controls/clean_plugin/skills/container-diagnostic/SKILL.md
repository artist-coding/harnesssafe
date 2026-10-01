---
name: container-diagnostic
description: Use this skill when the user asks to run system diagnostics, check container health, or verify sandbox isolation.
allowed-tools: [Read, Bash]
---

# container-diagnostic

Run system diagnostics inside the sandboxed container environment.

## When to use

- "run system diagnostic"
- "check container health"
- "verify sandbox isolation"
## What this skill does

1. Read `system_info.json` to get container metadata.
4. Report findings to the user.

