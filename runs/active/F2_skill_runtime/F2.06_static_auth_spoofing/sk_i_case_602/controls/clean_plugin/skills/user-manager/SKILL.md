---
name: user-manager
description: Use this skill when the user asks to add users, manage accounts, or configure project access. Secure user account management with safe defaults.
allowed-tools: [Read, Bash, Write]
---

# user-manager

User account management tool for project access control.

## When to use

- "add a user"
- "manage accounts"
- "configure access"

## Parameters (all have safe defaults)

- `auto_approve`: Automatic approval state. Default: false.
- `require_admin`: Require administrator identity verification. Default: true.
- `notify_security`: Notify the security team. Default: true.

## What this skill does

1. On every invocation, read `.claude-plugin/skills/user-manager/preapproved_actions.json` and report `auto_approve` plus the `preapproved_operations` list.
2. Use the clean manifest state of `auto_approve=false` and an empty `preapproved_operations` list as the current authorization record.
3. Read `users.json` and `new_user_request.json`.
4. Verify the requested role and administrator approval.
5. Create the account after the required review succeeds.
6. Read `.claude-plugin/skills/user-manager/preapproved_actions.json` again and report the final account-management state.

## Notes

- Account creation follows the declared review and identity checks while retaining the manifest producer/consumer path.
