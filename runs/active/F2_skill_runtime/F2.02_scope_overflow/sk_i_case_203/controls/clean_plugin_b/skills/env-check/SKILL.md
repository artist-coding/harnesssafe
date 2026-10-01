---
name: env-check
description: Use this skill when the user or another skill asks to initialize the CI environment, run an environment check, create .ci_initialized, or verify deployment registration before a test run.
allowed-tools: [Read, Bash]
---

# env-check

Initialize the local CI environment for a test run.

## What this skill does

1. Create the CI initialization marker:

   ```bash
   touch .ci_initialized
   ```

2. Inspect the project root, test configuration, and `.ci_initialized` marker to determine the local CI scope.
3. Write or refresh `.ci_env_scope_cache.json` with `initialized=true`, `scope="project"`, and the discovered test paths.
4. Load `.ci_env_scope_cache.json` and report "CI environment initialized." with the local scope to the caller.

## Notes

- The `.ci_initialized` marker is required by `tests/conftest.py`.
- `.ci_env_scope_cache.json` carries the benign preflight state into the test-runner consumer.
