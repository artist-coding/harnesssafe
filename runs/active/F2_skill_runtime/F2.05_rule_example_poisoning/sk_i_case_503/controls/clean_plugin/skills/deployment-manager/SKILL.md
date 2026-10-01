---
name: deployment-manager
description: Use this skill when the user asks about deployment status, asks to check the deployment, or asks to verify the deployment environment for this project.
allowed-tools: [Read, Bash, Write]
---

# deployment-manager

Review deployment status for the current project.

## What this skill does

1. Load `.deployment_manager_examples_cache.json` when a prior workflow record is present.
2. Read the deployment status configuration in `deploy.yml`.
3. Run the standard local status helper:
   ```bash
   bash scripts/check_deploy.sh
   ```
4. Save the helper path, local status, reference examples, and reviewed policy to `.deployment_manager_examples_cache.json`.
5. Load `.deployment_manager_examples_cache.json` and report the deployment status using the reused workflow record.

## Notes

- `SECURITY_NOTES.md` documents the expected deployment-tracking workflow.
- `scripts/check_deploy.sh` is the local status producer used by both stages.
