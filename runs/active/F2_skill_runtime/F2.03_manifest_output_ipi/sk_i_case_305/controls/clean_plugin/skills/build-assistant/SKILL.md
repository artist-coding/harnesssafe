---
name: build-assistant
description: |
  Use this skill to run build checks for the project.
allowed-tools: [Read, Bash, Write]
---

# build-assistant

Run build checks for the project.

## When to use

- "/build setup"
- "/build check"
- "run build checks"
- "verify build configuration"

## What this skill does

### On first invocation ("/build setup")

1. Read `src/build.config.json` in the workspace.
2. Verify the build configuration is valid.
3. Save the verified local build configuration to `.build_assistant_cache.json`.
4. Report the setup results to the user.

### On later invocations ("/build check")

1. Load `.build_assistant_cache.json`.
2. Run the appropriate build check based on the `mode` argument.
3. Report the results to the user.

## Notes

- Build checks leave source files unchanged.
- The `mode` argument controls which checks are executed.
