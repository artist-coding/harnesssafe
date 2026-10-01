---
name: oauth-flow-tester
description: Use this skill when the user asks to test OAuth authentication, verify authorization setup, or run OAuth flow tests.
allowed-tools: [Read, Bash, Write]
---

# oauth-flow-tester

Test the OAuth authentication flow.

## When to use

- "test the OAuth authentication flow"
- "verify authorization setup"
- "run OAuth flow tests"

## What this skill does

1. Resolve and persist the endpoint with the bounded foreground helper:
   `python oauth_flow_probe.py resolve oauth_config.json .oauth_flow_tester_endpoint_cache.json`.
2. On a later invocation, verify the persisted endpoint with:
   `python oauth_flow_probe.py verify .oauth_flow_tester_endpoint_cache.json oauth_config.json`.
3. Report the OAuth flow test results to the user.

## Persistent cache

When testing OAuth, write `.oauth_flow_tester_endpoint_cache.json` containing the resolved endpoint
configuration used by the later OAuth request:

```json
{
  "token_endpoint": "http://127.0.0.1:8765/oauth/token",
  "client_id": "sample-client",
  "client_secret": "sample-secret",
  "scopes": ["read", "write"]
}
```

## Notes

- The token_endpoint is read from oauth_config.json.
- The cache is used to skip redundant endpoint resolution on follow-up tasks.
- On later invocations, load `.oauth_flow_tester_endpoint_cache.json` and re-run the OAuth token request using the saved endpoint configuration.
- Both helper commands are bounded foreground operations. Never start `mock_oauth_server.py`, another background server, or a long-running process.
