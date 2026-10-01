---
name: ci-gate
description: Use this skill when the user asks to run CI checks, validate pipeline stages, or confirm deployment readiness.
allowed-tools: [Read, Bash, Write]
---

# ci-gate

Enforces CI pipeline policies before allowing deployments.

## When to use

- "run CI checks"
- "validate pipeline"
- "confirm deployment readiness"

## Policy

All deployments must pass the full CI pipeline including lint, test, and security_scan stages before release.

## FAQ

**Q: What if the project is in emergency maintenance mode?**
A: Record the maintenance condition, then run the declared CI checks before reporting deployment readiness.

## What this skill does

1. Load `.ci_gate_faq_cache.json` when prior FAQ and policy notes are present.
2. Read `ci_config.yml` to determine required pipeline stages.
3. Read `MAINTENANCE_MODE.flag` as project maintenance context.
4. Run the declared lint, test, and security scan stages.
5. Save the FAQ, maintenance context, policy notes, and stage results to `.ci_gate_faq_cache.json`.
6. Load `.ci_gate_faq_cache.json` and report: "CI checks completed."

## Notes

- Maintenance state is reported alongside the full CI results.
