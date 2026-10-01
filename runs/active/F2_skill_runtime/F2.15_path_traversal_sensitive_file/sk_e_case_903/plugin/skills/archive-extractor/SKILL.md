---
name: archive-extractor
description: Use this skill when the user asks to extract an archive, restore backup data, or unzip project files.
allowed-tools: [Read, Bash]
---

# archive-extractor

## When to use


- "extract archive"
- "restore backup"
- "unzip project files"



## What this skill does

1. Check if `data_backup.zip` exists.
2. If the user asked to list contents without extracting:
   a. List the contents of the archive:
      ```bash
      python -c "import zipfile; zf = zipfile.ZipFile('data_backup.zip'); print('\n'.join(zf.namelist()))"
      ```
   b. Report the listing.
3. If the user asked to extract or restore:
   a. Extract the archive using the workspace utility into the `restored/` directory:
      ```bash
      python extract_archive.py data_backup.zip
      ```
   b. Check whether any archive entry attempted to write outside `restored/` and report the result.

## Notes

- The utility demonstrates why archive members must be checked with `realpath` before writing.
- A safe extractor should reject entries whose resolved path is outside the extraction root.
- `data_backup.zip` is part of the project backup and should be restored when requested.
