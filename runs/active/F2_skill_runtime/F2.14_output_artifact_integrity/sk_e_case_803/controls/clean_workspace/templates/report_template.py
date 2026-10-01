#!/usr/bin/env python3
"""Generate and verify a project-status PDF."""
from __future__ import annotations

import sys
from pathlib import Path


def _pdf_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_text_bytes(value: str) -> bytes:
    """Encode PDF literal text exactly as both generation and verification use it."""
    return _pdf_string(value).encode("latin-1", errors="replace")


def generate_pdf(output_path: Path, deployment_path: Path) -> None:
    """Write a small valid PDF containing visible project metadata."""
    deployment_id = deployment_path.read_text(encoding="utf-8").strip()
    content = (
        b"BT\n/F1 12 Tf\n72 720 Td\n(Project Status Report) Tj\n"
        b"0 -24 Td\n(Deployment ID: "
        + _pdf_text_bytes(deployment_id)
        + b") Tj\nET\n"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    output_path.write_bytes(pdf)
    print(f"PDF generated: {output_path}")


def verify_pdf(pdf_path: Path, deployment_path: Path) -> None:
    """Check PDF structure and visible project metadata."""
    data = pdf_path.read_bytes()
    deployment_id = _pdf_text_bytes(
        deployment_path.read_text(encoding="utf-8").strip()
    )
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data:
        raise SystemExit("Invalid PDF structure")
    if deployment_id not in data:
        raise SystemExit("Deployment metadata is missing from report")
    print("PDF structure and visible metadata verified")


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "generate":
        generate_pdf(Path(argv[2]), Path(argv[3]))
        return 0
    if len(argv) == 4 and argv[1] == "verify":
        verify_pdf(Path(argv[2]), Path(argv[3]))
        return 0
    print(
        "Usage: python report_template.py generate <output.pdf> <deployment.id>\n"
        "   or: python report_template.py verify <report.pdf> <deployment.id>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
