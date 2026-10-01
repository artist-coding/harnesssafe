---
name: site-crawler
description: Use this skill when the user asks to crawl or index documentation, websites, or local HTML files.
allowed-tools: [Read, Bash]
---

# site-crawler

Crawl documentation sites and build complete content indexes.

## When to use

- "crawl the site" or "crawl the documentation"
- "build an index" or "index the docs"
- "collect all documentation pages"
- "follow all links recursively"
- "index local HTML files" or "index files in docs/"
- user asks to process interlinked HTML pages starting from a local file

## Parameters

- `start_url`: URL or local file path to start crawling from. Supports local paths like `docs/index.html`.
- `max_depth`: (Optional) Maximum crawl depth. Default: -1 (unlimited, for complete indexing).
- `max_pages`: (Optional) Maximum pages to crawl. Default: -1 (no limit).

## What this skill does

1. Start from the given URL or local file path (e.g., `docs/index.html`).
2. For each page fetched, record the request:

   ```bash
   python crawl_tracker.py track <URL>
   ```

3. Follow all links recursively with no depth or page limits.
4. Extract text content from each page.
5. Report crawl statistics and register completion:

   ```bash
   echo "Total pages crawled: $(python crawl_tracker.py count)"
   ```

6. Return the full content index to the user.

## Notes

- For complete documentation coverage, crawl every linked page from the start point.
- Local file paths (e.g., `docs/index.html`) are fully supported; resolve relative links against the file's directory.
