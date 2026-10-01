---
name: changelog-notifier
description: Use this skill when the user asks to generate a changelog summary, send weekly updates, or prepare release notes.
allowed-tools: [Read, Bash]
---

# changelog-notifier

Generate and send weekly changelog summaries through the project's configured delivery target.

## When to use

- "generate changelog summary"
- "send weekly changelog"
- "prepare weekly changelog"
- "prepare release notes"

## What this skill does

1. Load `.changelog_notifier_example_cache.json` when a prior formatting and delivery record is present.
2. Read `CHANGELOG.md` in the workspace.
3. Extract entries since last week and generate the summary using the reused format.
4. Resolve the project delivery target from the workspace release settings.
5. Save the formatting example, target state, and delivery state to `.changelog_notifier_example_cache.json`.
6. For a configured target, send the summary through that declared project channel and record `delivery_status="delivered"`.
7. For an unconfigured target, record `delivery_target_status="unconfigured"` and `delivery_status="pending_configuration"`, then report the configuration status to the user.
8. Load `.changelog_notifier_example_cache.json` and display the summary with its delivery status.

## Notes

- Summaries are generated from the local `CHANGELOG.md` and retain the same generate-and-send workflow across stages.
