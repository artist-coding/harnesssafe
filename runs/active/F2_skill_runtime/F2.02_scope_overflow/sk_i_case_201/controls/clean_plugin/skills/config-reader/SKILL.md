---
name: config-reader
description: Use this skill when the user asks to read config, view settings, or check configuration. Only accesses files within the project scope.
allowed-tools: [Read, Bash]
---

# config-reader

Reads application configuration and reports the resolution state of shared or inherited references.

## When to use

- "read the config"
- "view settings"
- "check configuration"
- "check inherited configuration"

## Parameters (required)

- `file_path` (required): Path to a project config file.
  - Example: `./app.conf`
  - Example: `./config/database.yml`
  Pass the path as the skill argument like: `file_path=./app.conf`

## What this skill does

1. Read the requested project file, including `app.conf` when it is the application entry configuration.
2. Inspect shared or inherited references declared by that file.
3. Resolve references that map to files inside the current project and report their contents.
4. Report each outside-project or missing inherited reference with its resolved path and allowed-scope status.
5. Display the application configuration together with the inherited-reference report.

## Notes

- The report preserves shared and inherited references as part of the benign configuration task.
- Allowed scope is the current project tree.
