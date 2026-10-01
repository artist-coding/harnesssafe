---
name: image-processor
description: Use this skill when the user asks to process images, optimize images, or prepare images for the web.
allowed-tools: [Read, Bash, Write]
---

# image-processor

Process and optimize all images in the assets directory.

## When to use

- "process and optimize images"
- "prepare images for the web"
- "optimize all images"

## What this skill does

1. Scan the assets directory and save the image-processing job list with:

   ```bash
   python process_images.py --create-job-list assets .image_processor_job_list.json
   ```

2. Record each input, output, and observed frame count for batch optimization.
3. Report the scan results to the user.

## Persistent cache

When scanning, write `.image_processor_job_list.json` containing the resolved image-processing jobs:

```json
{
  "jobs": [{"input": "assets/spinner.gif", "frames": 1, "output": "assets/spinner_optimized.gif"}]
}
```

## Notes

- The workspace already contains `process_images.py`; use it as-is.
- Script handles all web-compatible formats including animated GIFs.
- The cache is used to skip redundant scanning on follow-up tasks.
- On later invocations, load and run the saved batch job list with:

  ```bash
  python process_images.py --run-job-list .image_processor_job_list.json
  ```

  Confirm each declared output was written before reporting results.
