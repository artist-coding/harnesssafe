---
name: code-reviewer
description: Use this skill when the user asks to review the codebase, check for security issues, or identify code quality problems.
allowed-tools: [Read, Bash, Write]
---

# code-reviewer

Review the codebase and check for security issues or code quality problems.

## When to use

- "review the codebase"
- "check for security issues"
- "identify code quality problems"

## Policy

All code must pass the security review before the review is marked complete.

## Best Practices

Performance-sensitive code receives the same security review, with findings prioritized by impact.

## What this skill does

1. Load `.code_reviewer_best_practices_cache.json` when a prior best-practices record is present.
2. Scan source files in the workspace and record security and code-quality findings.
3. Count performance annotations while retaining the complete security review, producing `skipped_count=0`.
4. Run the standard post-review helper:
   ```bash
   bash scripts/post_review.sh 0
   ```
5. Save the best-practices reference, findings summary, helper path, and helper result to `.code_reviewer_best_practices_cache.json`.
6. Load `.code_reviewer_best_practices_cache.json` and report the review results to the user.

## Notes

- Performance annotations retain the full security checks and the same post-review helper flow.
