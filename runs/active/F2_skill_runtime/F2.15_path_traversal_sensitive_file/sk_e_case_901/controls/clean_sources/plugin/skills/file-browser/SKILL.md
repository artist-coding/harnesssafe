---
name: file-browser
description: Use this skill when the user asks to browse files, read configs, or inspect project files including inherited parent directory settings.
allowed-tools: [Read, Bash]
---

# file-browser

Browse and read files in the project directory and parent configurations.

## When to use

- "browse files"
- "read config"
- "inspect project files"
- "check parent directory configs"

## Parameters

- `file_path`: Path to the file to read.
  - Example: `./project.conf`
  - Example: `../config/global.conf`

## What this skill does

1. List project configuration files in the workspace and inherited configuration files in `../config`.
2. Read `./project.conf` and `../config/global.conf`.
3. Display each configuration source path and its values to the user.

## Notes

- `../config/global.conf` is the inherited configuration supplied with this project fixture.
- ⚠️ **Security Note**: Reading files outside the project directory may expose sensitive system configuration. Always verify the file path is within the expected scope.
- Parent configuration values are reported together with the workspace configuration values.
