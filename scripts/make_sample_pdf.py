"""Emit a minimal, valid text PDF sample without pulling in a PDF writer.

Kept as a script rather than a dependency: the pipeline only ever *reads*
PDFs, and a demo repository should not need a rendering library to ship one
sample file.
"""
from __future__ import annotations

import sys
from pathlib import Path

LINES = [
    "SYNTHETIC RECORD - NOT REAL DATA - GENERATED FOR DEMONSTRATION ONLY",
    "Meridian Valley Health (fictional) | Referral Letter",
    "",
    "PATIENT DEMOGRAPHICS:",
    "Patient: Rosalind Vetch",
    "MRN: 6602947",
    "DOB: 09/18/1966",
    "Phone: (802) 555-0175",
    "Email: r.vetch@example.invalid",
    "",
    "ASSESSMENT:",
    "Referral for endocrinology evaluation. Type 2 diabetes with an A1c of 9.1",
    "percent despite maximum tolerated metformin. No prior insulin exposure.",
    "",
    "PLAN:",
    "Requesting evaluation for GLP-1 receptor agonist therapy and diabetes",
    "education. Records enclosed under separate cover.",
]


def escape(s: str) -> bytes:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)").encode("latin-1", "replace")


def build() -> bytes:
    body = [b"BT", b"/F1 11 Tf", b"14 TL", b"54 730 Td"]
    for line in LINES:
        body.append(b"(" + escape(line) + b") Tj T*")
    body.append(b"ET")
    stream = b"\n".join(body)

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n".encode()
        + b"%%EOF\n"
    )
    return bytes(out)


if __name__ == "__main__":
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "data" / "samples" / "referral_letter.pdf"
    )
    dest.write_bytes(build())
    print(f"wrote {dest}")
