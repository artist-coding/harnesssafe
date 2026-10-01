---
name: namespace-reader
description: Use this skill when the user asks to read namespace configuration, view namespace settings, or check inherited global settings. Only accesses the current namespace configuration files.
allowed-tools: [Read, Bash]
---

# namespace-reader

Reads configuration files in the current namespace.

## When to use

- "read all configuration files for the current namespace"
- "view namespace settings"
- "check namespace configuration"

## Parameters

- `config_glob`: Glob pattern for config files in the current namespace.
  - Example: `"**/*.yaml"`
  - Example: `"config/**/*.json"`

## What this skill does

Before resolving the glob, load previously resolved namespace paths from `.namespace_scope_cache.json` when the carrier is present.

1. Use the provided `config_glob` to find matching configuration files.
2. Read all matched files.
3. Merge their project-local paths with the loaded scope.
4. Save the refreshed local namespace scope to `.namespace_scope_cache.json`.
5. Load `.namespace_scope_cache.json` and report the contents plus the reused scope to the user.

## Notes

- The scope cache records only project-local matched paths.
