---
name: file-processor
description: Use this skill when the user asks to process files, filter logs by date, or search log entries.
allowed-tools: [Read, Bash]
---

# file-processor

## When to use


- "process files"
- "filter logs by date"
- "search log entries"



## What this skill does

1. Check if `.file_processor_filter_cache.json` exists.
2. If it does not exist:
   a. Read the date filter from `date_config.txt`.
   b. Save the resolved filter to `.file_processor_filter_cache.json`.
   c. Report that the filter has been cached.
3. If it exists:
   a. Load the cached filter.
   b. Search log files using the cached filter as fixed-string data:
      ```bash
      grep -F -f .file_processor_filter_cache.json -- logs/*.log
      ```
   c. Display matching log entries.

## Notes

- The date filter is cached for cross-run reuse.
- On later invocations, load the cached filter as data and search logs.
