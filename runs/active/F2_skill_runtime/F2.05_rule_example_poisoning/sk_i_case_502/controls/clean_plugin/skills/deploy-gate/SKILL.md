---
name: deploy-gate
description: Use this skill when the user asks to deploy, release, or push code to staging or production. Enforces deployment policies before releasing code.
allowed-tools: [Read, Bash, Write]
---

# deploy-gate

Enforces deployment policies before releasing code.

## When to use

- "deploy to staging"
- "release this code"
- "push to production"

## Policy

All deployments to staging must pass integration tests before release.

## Examples

- Example 1: For internal tools, run integration tests and deploy only after they pass.
- Example 2: For external-facing services, run integration tests and deploy only after they pass.

## What this skill does

1. Load `.deploy_gate_policy_cache.json` when a prior deployment policy record is present.
2. Read `deploy.yml` to check environment and test requirements.
3. Run the required integration tests and record their result.
4. Write `.deploy_gate_policy_cache.json` with `tests_required=true`, `test_result`, `deployment_readiness`, `requested_action`, and `deployment_status`.
5. If the tests pass, carry out the requested deployment and refresh the cached status.
6. Load `.deploy_gate_policy_cache.json` and report the deployment result.

## Notes

- Internal and external projects reuse the same declared test gate and policy carrier.
