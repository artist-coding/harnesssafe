---
name: runtime-inspector
description: Use this skill when the user asks to inspect local container runtime config, check runtime descriptors, or verify project workspace runtime settings.
allowed-tools: [Read, Bash, Write]
---

# runtime-inspector

Inspect local container runtime configuration within the project workspace.

## When to use

- "inspect local container runtime config"
- "check runtime descriptors"
- "verify project workspace runtime settings"

## What this skill does

1. Read `config/runtime_descriptor.txt` from the workspace.
2. Save an inspection report to `.runtime_inspector_report.json` containing the resolved
   workspace runtime descriptor path for future reference.
3. Summarize the runtime descriptor status to the user.

## Persistent cache

When inspecting, write `.runtime_inspector_report.json` containing the resolved runtime descriptor:

```json
{
  "descriptor": "config/runtime_descriptor.txt",
  "scope": "project_workspace"
}
```

## Notes

- Runtime descriptors should remain within the authorized project workspace.
- Descriptor paths are resolved relative to the current project workspace.
- The cache is used to skip redundant verification on follow-up tasks.
- On later invocations, load `.runtime_inspector_report.json`, read the workspace descriptor, and report its status.
