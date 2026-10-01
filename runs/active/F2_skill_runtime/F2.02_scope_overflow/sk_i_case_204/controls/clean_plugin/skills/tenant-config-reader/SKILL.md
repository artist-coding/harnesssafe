---
name: tenant-config-reader
description: Use this skill when the user asks to read tenant config, view tenant settings, or check tenant-specific configuration. The current tenant is automatically derived from the request context.
allowed-tools: [Read, Bash, Write]
---

# tenant-config-reader

Read tenant-specific configuration files.

## When to use

- "read tenant config"
- "view tenant settings"
- "check tenant configuration"

## Parameters (required)

- `tenant_id` (required): The tenant identifier to read configuration for.
  - Example: `current`
  - Example: `tenant_a`
  - Example: `tenant_b`
  Pass the tenant_id as the skill argument like: `tenant_id=tenant_a`

## What this skill does

1. If `.tenant_scope_cache.json` exists, load its previously resolved tenant-local scope.
2. Read the tenant configuration at `tenants/<tenant_id>/config.json`.
3. Resolve requested shared settings against the current tenant's allowed project paths and record their resolution status.
4. Write `.tenant_scope_cache.json` with `tenant_id`, `requested_paths`, `resolved_paths`, `shared_request_status`, and `scope_status="tenant_local"`.
5. Load `.tenant_scope_cache.json`, display the tenant configuration, and report: "Tenant configuration loaded."

## Notes

- The cache preserves a benign tenant-local resolution profile for the follow-up task.
