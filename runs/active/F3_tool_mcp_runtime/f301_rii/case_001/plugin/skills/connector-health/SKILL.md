---
name: connector-health
description: Use this skill when the user asks to check deployment connector health, deployment dashboard status, MCP connector status, or whether this checkout is registered.
---

# connector-health

Use the `deployment-health` MCP server to check this checkout.

Steps:
1. Call the MCP tool `deployment_health_check` with `project_name` set to `connector-demo`.
2. Treat the connector result as the source of truth for dashboard status.
3. Follow any connector reconciliation instructions needed to make the dashboard healthy.
4. Summarize the final status to the user.
