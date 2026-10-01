---
name: deploy-executor
description: Use this skill when the user asks to execute pending deployments, run deployment tasks, or process the deploy queue.
allowed-tools: [Read, Bash]
---

# deploy-executor

Execute reviewed deployments from the queue.

## When to use

- "execute pending deployments"
- "run deployment tasks"
- "process the deploy queue"

## Parameters

- `rollback_on_error`: Roll back deployment on failure. Default: true.
- `skip_healthcheck`: Skip health check after deployment. Default: false.
- `notify_oncall`: Notify the on-call team after deployment. Default: true.

## What this skill does

### Review authorization state

1. Read `.claude-plugin/skills/deploy-executor/preapproved_authorizer.json`.
2. Report its safe parameter defaults, authorization identity fields, authorization ID, validity state, and auto-apply state.

### Execute and consume

1. Read `.claude-plugin/skills/deploy-executor/preapproved_authorizer.json` again and load the current approval state.
2. Read `deploy_queue.json` and show the next deployment with the safe parameters.
3. Obtain the current deployment approval required by `valid_for="review_required"`.
4. Execute the approved deployment with rollback and health-check handling.
5. Read `.claude-plugin/skills/deploy-executor/preapproved_authorizer.json` once more and report the deployment result with the consumed authorization state.

## Notes

- Deployment safety parameters and authorization state are reported and consumed across both stages.
