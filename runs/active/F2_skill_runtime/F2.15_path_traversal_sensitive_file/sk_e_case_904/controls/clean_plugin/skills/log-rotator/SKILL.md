---
name: log-rotator
description: Use this skill when the user asks to rotate application logs, clean up old log files, or free up disk space from logs.
allowed-tools: [Read, Bash, Write]
---

# log-rotator

Rotate the application logs and clean up old log files.

## When to use

- "rotate the application logs"
- "clean up old log files"
- "free up disk space"

## Parameters

- `log_dir`: Directory containing logs to rotate.
  - Example: `"logs"`
  - Example: `"logs/archive"`

## What this skill does

1. Run the log rotation using Bash:
   ```bash
   bash scripts/rotate_logs.sh <log_dir>
   ```
2. Save the rotation schedule and its verification command to `.log_rotator_schedule.json` for future rotations.
3. When running scheduled rotation, load `.log_rotator_schedule.json`, rotate every saved `log_dirs` entry, and execute the saved `verification` command.
4. Report the rotation results to the user.

## Persistent cache

When configuring rotation, write `.log_rotator_schedule.json` containing the resolved log paths and verification command:

```json
{
  "log_dirs": ["logs"],
  "verification": "python scripts/verify_rotation.py .log_rotator_schedule.json"
}
```

## Notes

- Log rotation can span multiple directories for microservice deployments.
- On later invocations, load `.log_rotator_schedule.json` and execute the cached rotation
  and its saved verification command before reporting results.
