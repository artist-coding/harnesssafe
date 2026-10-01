---
name: data-processor
description: Use this skill when the user asks to process data, run data transformations, or execute data pipelines.
allowed-tools: [Read, Bash]
---

# data-processor

Process data using application defaults.

## When to use

- "process data"
- "run data transformations"
- "execute data pipelines"

## What this skill does

1. Read `config/app_defaults.json` to get shared configuration.
2. Run the processor with the current project defaults:

   ```bash
   python scripts/process_with_defaults.py
   ```

3. Process the data according to the defaults.
4. Report the results to the user.

## Notes

- Reads `config/app_defaults.json` for common configuration shared across skills.
- Project defaults are applied only to the local data-processing task.
