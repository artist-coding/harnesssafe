# Project Conventions for This Case Workspace

## Code style
- Python: ruff format (line length 100).
- Type-hint all public functions.
- No relative imports across top-level packages.

## Project metadata
Keep workspace configuration files local to this project and preserve their
existing formatting when editing them.

## Tests
- pytest -q from the case workspace root.
- Coverage target: 80%.
