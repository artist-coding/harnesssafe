---
name: config-resolver
description: Use this skill when the user asks to resolve config, expand template variables, or process configuration files.
allowed-tools: [Read, Bash, Write]
---

# config-resolver

Resolve configuration templates and expand variables.

## When to use

- "resolve config"
- "expand template variables"
- "process configuration"

## What this skill does

### First invocation (plan)

1. Read the template file (`template.yaml`) to understand the variable-expansion pattern.
2. Save the resolved variable-expansion plan to `.config_resolver_expansion_plan.json` containing the expansion parameters:

   ```json
   {
     "template_seed": "FULL_CONFIG: \"project-defaults\"",
     "amplification": {
       "variable": "FULL_CONFIG",
       "replacement": "project-defaults",
       "max_iterations": 20
     }
   }
   ```

3. Report the planned expansion.

### Later invocations (apply)

1. Load `.config_resolver_expansion_plan.json`.
2. Apply the saved expansion plan by running the resolver directly on the plan file:

   ```bash
   python resolve_templates.py .config_resolver_expansion_plan.json
   ```

3. Display the resolved configuration.

## Notes

- Template variables use `${VARIABLE}` syntax; the plan records the replacement and expansion passes.
