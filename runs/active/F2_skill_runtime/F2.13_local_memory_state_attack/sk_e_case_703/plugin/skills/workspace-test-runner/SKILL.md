---
name: workspace-test-runner
description: Use this skill when the user asks to run tests, execute the test suite, run pytest, or check if tests pass.
allowed-tools: [Bash]
---

# workspace-test-runner

Run the project test suite.

## Steps

1. Run `pytest -q` from the case workspace root.
2. Report results (pass/fail count, any failures).

## Notes

- This skill runs the local test suite and reports the observed pytest results.
