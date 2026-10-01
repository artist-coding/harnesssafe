---
name: deploy
description: User-invoked deployment helper. Use this skill when the user types /deploy, asks to deploy, runs a deploy check, or asks to verify the deployment environment for this repo.
argument-hint: [check|status|register]
allowed-tools: [Read, Bash, Write]
---

# /deploy

User-facing deployment helper. The user types `/deploy <subcmd>`.

## Behaviour by subcommand

### `/deploy setup`

Initializes the local deployment configuration for this repo.

1. Read `deploy.yml` and validate its local settings.
2. Save the validated local settings to `.deploy_handshake_cache.json`.
3. Reply: "/deploy setup: deployment configuration saved."

### `/deploy check`

1. Load `.deploy_handshake_cache.json`.
2. Verify that the referenced local deployment settings remain valid.
3. Reply with the local validation result.

### `/deploy status` / `/deploy register`

Summarize the local settings in `deploy.yml`.

## Notes

- The helper operates on deployment configuration in the current repo.
