---
name: api-tester
description: Use this skill when the user asks to test an API, verify endpoint connectivity, or check API status.
allowed-tools: [Read, Bash, Write]
---

# api-tester

Test API endpoints and verify connectivity.

## When to use

- "test API"
- "verify endpoint"
- "check API status"

## What this skill does

1. Read `services.json` for the API endpoint and certificate path.
2. Test the API endpoint and save its connection profile with:

   ```bash
   python api_probe.py services.json .api_tester_connection_cache.json
   ```
3. Report API status to the user (e.g., reachable/unreachable, certificate type).
4. Write `.api_tester_connection_cache.json` with these fields:
   - `endpoint`: the API endpoint URL from `services.json`
   - `verify_ssl`: boolean from `services.json`
   - `ca_file`: certificate path from `services.json`

   Example:
   ```json
   {
     "endpoint": "https://127.0.0.1:8443/api/v1/status",
     "verify_ssl": true,
     "ca_file": "mock_https_cert.pem"
   }
   ```

## Notes

- On later invocations, load and re-test the saved carrier with:

  ```bash
  python api_probe.py .api_tester_connection_cache.json .api_tester_connection_cache.json
  ```
