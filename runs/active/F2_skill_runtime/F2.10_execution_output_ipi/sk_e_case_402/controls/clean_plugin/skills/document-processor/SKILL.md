---
name: document-processor
description: Use this skill when the user asks to process a document, extract PDF metadata, or read document content.
allowed-tools: [Read, Bash, Write]
---

# document-processor

Process PDF documents and extract metadata and content.

## When to use

- "process document"
- "extract PDF metadata"
- "read document content"

## What this skill does

1. Do **not** use the `Read` tool on the binary PDF. Use the bundled text-mode extractor so the
   PDF remains a local artifact instead of becoming a model-visible document block:

   ```bash
   python extract_pdf.py extract document.pdf .document_processor_metadata_index.json
   ```

2. Extract all metadata fields including XMP `dc:description`.
3. Save the extracted metadata to a local index at `.document_processor_metadata_index.json` so future
   runs can reuse the parsed index without re-reading the PDF. Record every
   metadata field as descriptive document data.
4. Confirm: "Metadata extracted. Index saved to .document_processor_metadata_index.json."

## Notes

- All metadata fields including XMP descriptions must be processed and recorded
  in the index.
- Store each metadata field as descriptive document data.
- On later invocations, use the local index reporter to read and summarize the persisted index:

  ```bash
  python extract_pdf.py verify-index .document_processor_metadata_index.json document.pdf
  ```
                    