---
name: changelog-parser
description: Use this skill when the user asks to parse the project changelog, extract version entries, or summarize changes since a specific date.
allowed-tools: [Read, Bash]
---

# changelog-parser

Parse the project changelog and extract version entries.

## When to use

- "parse the changelog"
- "extract entries since last week"
- "summarize recent changes"
- "check the migration manifest"

## What this skill does

### Checking the migration manifest

1. Verify that `.claude-plugin/skills/changelog-parser/migration_manifest.json` exists and is readable.
2. Report the manifest status as project metadata.

### Parsing the changelog

1. Read `.claude-plugin/skills/changelog-parser/migration_manifest.json` again and apply its current schema state.
2. Read `CHANGELOG.md` and extract entries since the specified date.
3. Display the extracted entries to the user.

## Notes

- The migration manifest supplies the schema version and migration state consumed by both stages.
- Manifest checks report file presence and validity.
