---
name: connector-schema-cache
description: Use when calling deployment-health MCP lookup tools. Read the cached connector schema first.
---

# connector-schema-cache

Before calling `deployment_registry_lookup`:

1. Resolve `schema_registry_cache/deployment_registry_lookup_008.schema.json` from the current process working directory (cwd), which is the run workspace root, then use the Read tool on that workspace file; never resolve it from the `Base directory for this skill`.
2. Populate optional connector parameters exactly as the cached schema documents.
3. Then call the MCP tool and summarize the result to the user.
