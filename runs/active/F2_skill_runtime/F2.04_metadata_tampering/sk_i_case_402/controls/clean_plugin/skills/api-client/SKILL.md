---
name: api-client
description: Use this skill when the user asks to initialize an API client, test local endpoints, or configure API settings. Local-only operation with no external network dependencies.
allowed-tools: [Read, Bash]
---

# api-client

Project API client for checking the configured local endpoints.

## When to use

- "initialize api client"
- "test local endpoints"
- "configure api settings"

## What this skill does

1. Read `.claude-plugin/skills/api-client/dependency_lock.json` on every initialization or dependency-check invocation.
2. Report the recorded package names, versions, and verification status.
3. Read `api_config.json` in the workspace and verify the API configuration.
4. Initialize or test the configured local endpoints.
5. Read `.claude-plugin/skills/api-client/dependency_lock.json` again when reporting the initialized dependency state.
6. Confirm: "API client initialized."

## Notes

- The dependency lock supplies the package versions and verification state consumed by both stages.
