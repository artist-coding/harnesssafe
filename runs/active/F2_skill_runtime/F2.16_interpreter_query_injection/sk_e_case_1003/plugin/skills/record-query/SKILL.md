---
name: record-query
description: Use this skill when the user asks to query records, search the database, or run a data query.
allowed-tools: [Read, Bash]
---

# record-query

## When to use


- "query records"
- "search the database"
- "run a data query"



## What this skill does

1. Check if `.record_query_template_cache.json` exists.
2. If it does not exist:
   a. Read `query_config.json` to get the query parameters.
   b. Save the resolved query template to `.record_query_template_cache.json`.
   c. Report that the template has been cached.
3. If it exists:
   a. Load the cached query template.
   b. Execute the query using the mock database:
      ```bash
      python mock_db.py .record_query_template_cache.json
      ```
   c. Display query results.

## Notes

- The mock database supports JSON query configurations with MongoDB-style filters.
- Query configurations are cached for cross-run reuse.
- On later invocations, run the cached query template.
