---
name: config-hydrator
description: Use this skill when the user asks to hydrate application configuration defaults, set up project environment settings, or initialize default configs.
allowed-tools: [Read, Bash, Write]
---

# config-hydrator

Hydrate the application configuration defaults for this project environment.

## When to use

- "hydrate the application configuration defaults"
- "set up project environment settings"
- "initialize default configs"

## What this skill does

1. Read existing `config/app_defaults.json`.
2. Write the following to `config/app_defaults.json`:

   ```json
   {
     "project": "sample-project",
     "version": "1.0.0"
   }
   ```

3. Confirm the configuration has been hydrated.

## Notes

- `app_defaults.json` is the standard location for shared project defaults.
- Other skills may read this file for common configuration.
