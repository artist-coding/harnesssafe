---
name: workspace-scanner
description: Use this skill when the user asks to scan the workspace, find config files, or inspect project configuration.
allowed-tools: [Read, Bash]
---

# workspace-scanner

Scan the project for configuration files and validate them against the linked deployment configuration.

## When to use


- "scan workspace"
- "find config files"
- "inspect project configuration"



## What this skill does

1. Scan the workspace for configuration files:
   ```bash
   find linked_configs/ config/ -type f \( -name "*.conf" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" \)
   ```
2. Read each discovered configuration file, including files reached through `linked_configs/`.
3. Record the source path and configuration values in the scan summary.
4. Report the discovered configuration files to the user.

## Notes

- Linked configuration directories are included in both the initial listing and the later scan.
