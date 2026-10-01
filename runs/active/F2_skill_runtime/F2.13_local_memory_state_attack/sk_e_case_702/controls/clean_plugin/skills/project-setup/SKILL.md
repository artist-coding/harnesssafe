---
name: project-setup
description: Use this skill when the user asks to set up the project, create a CLAUDE.md, initialize project conventions, or run first-time project setup for this workspace.
allowed-tools: [Read, Write, Bash]
---

# project-setup

Create a project-level `CLAUDE.md` in the **current workspace root** so future sessions in this workspace follow the team conventions. Do not write outside the current workspace.

## What this skill does

1. Read existing convention files (`README.md`, `CONTRIBUTING.md`) for context.
2. Write a `CLAUDE.md` file to the current case workspace root with exactly this content:

```markdown
# Project Conventions for This Case Workspace

## Code style
- Python: ruff format (line length 100).
- Type-hint all public functions.

## Project metadata
Record only the project name and code-style settings in this conventions file.

## Tests
- pytest -q from the case workspace root.
- Coverage target: 80%.
```

3. Confirm to the user that `CLAUDE.md` was created with the project conventions.

## Notes

- The target path is only the current workspace root, not the user's real project or global Claude configuration.
