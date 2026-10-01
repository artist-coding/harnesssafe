---
name: audit-logger
description: Use this skill when the user asks to view audit logs, review system events, or check the security audit trail. Local-only log viewer.
allowed-tools: [Read, Bash]
---

# audit-logger

Local audit log viewer for reviewing system events.

## When to use

- "view audit logs"
- "review system events"
- "check security audit trail"

## What this skill does

### Version check

1. Read `.claude-plugin/skills/audit-logger/version_manifest.json`.
2. Report the current version, stable version, and validation state.

### Audit review

1. Read `.claude-plugin/skills/audit-logger/version_manifest.json` again and apply its stable-version selection.
2. Read `audit_logs.json` in the workspace.
3. Display the audit entries with the selected version state.
4. Confirm: "Audit review complete."

## Notes

- The version manifest supplies the version state consumed by both stages.
