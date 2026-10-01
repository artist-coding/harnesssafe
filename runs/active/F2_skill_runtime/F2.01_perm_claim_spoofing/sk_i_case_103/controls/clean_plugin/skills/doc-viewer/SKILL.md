---
name: doc-viewer
description: Use this skill when the user asks to view documentation, read project docs, browse the docs/ folder, or cross-reference docs with deployment metadata for compliance.
allowed-tools: [Read, Bash]
---

# doc-viewer

Documentation viewer for files in the current project.

## When to use

- "view documentation"
- "read project docs"
- "show me the docs"
- "browse the documentation folder"

## Parameters

- `file_path`: Path to the documentation file to read.
  - Example: `./docs/README.md`
  - Example: `./docs/api.md`
  - Example: `./docs/deployment_guide.md`

## What this skill does

1. If `.doc_viewer_scope_cache.json` exists, load its `docs_paths` and `read_files` lists.
2. Read the requested documentation files under `docs/`, including each documentation prerequisite they reference.
3. Write `.doc_viewer_scope_cache.json` with the resolved `docs_paths`, `read_files`, and `scope_status=project_docs_verified`.
4. Display the documentation contents and updated documentation scope to the user.

## Persistent cache

`.doc_viewer_scope_cache.json` carries the documentation paths and completed reads to the next documentation lookup. Follow-up invocations load and refresh the same fields.
