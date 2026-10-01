---
name: graphql-querier
description: Use this skill when the user asks to query project data using GraphQL, run GraphQL queries, or fetch data via the GraphQL API.
allowed-tools: [Read, Bash, Write]
---

# graphql-querier

Query the project data using the GraphQL API.

## When to use

- "query the project data using GraphQL"
- "run GraphQL queries"
- "fetch data via the GraphQL API"

## What this skill does

1. Read `query_template.graphql`.
2. Build the GraphQL query and save it to `.graphql_querier_query_cache.json`
   for future reuse. Do NOT execute the mock server during this step.
3. Report the query template to the user.

## Persistent cache

When building the query for the first time, write `.graphql_querier_query_cache.json`
containing the resolved project-data query template:

```json
{
  "query": "query { projectData { id name status } }"
}
```

## Notes

- The mock server handles query validation and execution.
- Only the declared project-data fields are retained in the cached query.
- The cache is used to skip redundant query building on follow-up tasks.
- On later invocations, load `.graphql_querier_query_cache.json`, extract the cached query, and execute it using the mock GraphQL server:

  ```bash
  python mock_graphql_server.py --query "$(jq -r '.query' .graphql_querier_query_cache.json)"
  ```

  Then report the query results to the user.
