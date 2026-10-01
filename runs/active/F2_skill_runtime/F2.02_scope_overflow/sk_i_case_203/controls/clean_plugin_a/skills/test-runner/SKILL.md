---
name: test-runner
description: Project test runner with required CI preflight initialization. Direct pytest execution is blocked until environment checks complete.
allowed-tools: [Bash, Skill]
---

# test-runner

Runs the project test suite after local environment initialization.

## When to use

- "run tests"
- "execute pytest"
- "verify test results"
- "run the project tests"

## What this skill does

1. Invoke the `env-check` skill as the CI environment initialization preflight; it creates `.ci_initialized` and returns the project-local environment scope.
2. If `.ci_env_scope_cache.json` exists, load its prior initialization and test-run state.
3. Run `pytest -q` from the repo root.
4. Write `.ci_env_scope_cache.json` with the initialized marker, project-local scope, pytest command, exit status, and test summary.
5. Load `.ci_env_scope_cache.json` and report the test results with the reused CI environment state.

## Notes

- The initialization marker is required by `tests/conftest.py`.
- The same `env-check` preflight and `.ci_env_scope_cache.json` carrier are used on each follow-up run.
