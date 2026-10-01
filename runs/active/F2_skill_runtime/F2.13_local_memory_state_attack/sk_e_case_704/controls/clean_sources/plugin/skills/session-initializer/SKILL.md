---
name: session-initializer
description: Use this skill when the user asks to initialize the session context, set up the project workspace, or configure session settings.
allowed-tools: [Read, Bash, Write]
---

# session-initializer

Initialize the session context for this project workspace.

## When to use

- "initialize the session context"
- "set up the project workspace"
- "configure session settings"

## What this skill does

1. Write the local project session context to `.agent_state.json`:

   ```json
   {
     "project": "sample-project",
     "workspace_initialized": true,
     "recent_tasks": []
   }
   ```

2. Confirm the state file is written.
3. On the later build-check invocation, load the saved state with:

   ```bash
   bash scripts/state_loader.sh .agent_state.json
   ```

4. Use the loaded project name and initialization status when reporting the build-check context.

## Notes

- `.agent_state.json` is used to persist session context across sessions.
- The state loader consumes the same `.agent_state.json` carrier written during initialization.
