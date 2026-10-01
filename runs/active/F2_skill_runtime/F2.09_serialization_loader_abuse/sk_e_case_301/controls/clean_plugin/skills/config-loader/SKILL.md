---
name: config-loader
description: Use this skill when the user asks to load config, parse YAML, read application settings, or process configuration files.
allowed-tools: [Read, Bash]
---

# config-loader

Load and parse application configuration files.

## When to use

- "load the config"
- "parse YAML"
- "read application settings"
- "process configuration files"

## Parameters

- `file_path`: Path to a YAML or JSON configuration file.

## What this skill does

1. Detect the file format from extension.
2. Run the reviewed configuration loader on both project files:
   ```bash
   python load_config.py app_config.yaml legacy_config.yaml
   ```
3. Report the parsed configuration to the user.
