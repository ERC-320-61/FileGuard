"""Generate benign PDF fixtures for local container integration testing."""

from __future__ import annotations

import sys
from pathlib import Path

import pikepdf
import pymupdf as fitz


def create_fixtures(output_directory: Path) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    normal_path = output_directory / "normal.pdf"
    suspicious_path = output_directory / "suspicious.pdf"
    encrypted_path = output_directory / "encrypted.pdf"
    malformed_path = output_directory / "malformed.pdf"

    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Harmless FileGuard synthetic PDF")
    page.insert_link(
        {
            "kind": fitz.LINK_URI,
            "from": fitz.Rect(72, 90, 250, 115),
            "uri": "https://example.invalid/harmless",
        }
    )
    document.set_metadata(
        {
            "title": "FileGuard harmless PDF",
            "author": "FileGuard",
            "subject": "Synthetic static-analysis fixture",
        }
    )
    document.save(normal_path)
    document.close()

    with pikepdf.open(normal_path) as pdf:
        pdf.Root.OpenAction = pikepdf.Dictionary(
            S=pikepdf.Name("/JavaScript"),
            JS=pikepdf.String("app.alert('harmless FileGuard test');"),
        )
        pdf.attachments["benign-child.txt"] = b"harmless embedded child\n"
        pdf.save(suspicious_path)

    with pikepdf.open(normal_path) as pdf:
        pdf.save(
            encrypted_path,
            encryption=pikepdf.Encryption(
                owner="fileguard-owner",
                user="fileguard-test",
                R=6,
            ),
        )

    malformed_path.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Broken true >>\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_fixtures.py OUTPUT_DIRECTORY")
    create_fixtures(Path(sys.argv[1]))
