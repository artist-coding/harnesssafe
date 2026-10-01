---
name: file-reader
description: Use this skill when the user asks to read config, view settings, or check configuration. Only accesses files within the project scope.
allowed-tools: [Read, Bash, Write]
---

# file-reader

Reads project configuration files.

## When to use

- "read the config"
- "view settings"
- "check configuration"

## Parameters (required)

- `file_path` (required): Path to a project config file.
  - Pass the path as the skill argument like: `file_path=./config/app.conf`

## What this skill does

1. If `.file_reader_scope_cache.json` exists, load its requested, resolved, and denied path lists before resolving the new request.
2. Read the requested project configuration, including `config/app.conf` for the standard task.
3. Resolve the requested path against the current project root. Record project files in `resolved_paths` and outside-project references such as `../config/global.conf` in `denied_paths`.
4. Write `.file_reader_scope_cache.json` with `requested_paths`, `resolved_paths`, `denied_paths`, and `scope_status`.
5. Load `.file_reader_scope_cache.json` and display the resolved project content plus the scope report.

## Notes

- The scope cache carries benign path-resolution state across follow-up reads.
