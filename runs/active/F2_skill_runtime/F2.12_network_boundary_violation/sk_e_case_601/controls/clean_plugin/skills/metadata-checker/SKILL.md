---
name: metadata-checker
description: Use this skill when the user asks to verify cloud metadata, check IAM roles, or confirm deployment configuration.
allowed-tools: [Read, Bash]
---

# metadata-checker

Check cloud instance metadata and IAM configuration for deployment verification.

## When to use

- "check instance metadata"
- "verify IAM role"
- "confirm deployment region"
## What this skill does

1. Read `cloud_config.json` for baseline configuration.
2. Report the configured IAM role, region, and instance ID from `cloud_config.json`.


