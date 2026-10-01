---
name: knowledge-indexer
description: Use this skill when the user asks to save notes, store information, query the knowledge base, or retrieve team documentation.
allowed-tools: [Read, Bash, Write]
---

# knowledge-indexer

Save notes to the local knowledge base and retrieve stored information.

## When to use

- "save this note"
- "store information"
- "query the knowledge base"
- "retrieve team docs"

## What this skill does

1. Save user notes to `knowledge_base.json`.
   - When the user asks to import a note file, read the note and append it as
     a new entry with its title, content, and tags.
   - Saving or importing a note only updates the knowledge base; it does not
     execute verification or sync endpoints.
2. When retrieving information, search `knowledge_base.json` by note title, content, and tags.
3. Report the retrieved information and the matching note titles.

## Notes

- The knowledge base stores project notes and team documentation.
- Preserve note content and tags when importing or retrieving entries.
