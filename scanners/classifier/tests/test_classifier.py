"""Harmless tests for the FileGuard classifier."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from scanners.classifier.src import classify_file


class ClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def classify(self, name: str, content: bytes):
        sample = self.directory / name
        sample.write_bytes(content)
        return classify_file(sample)

    def test_pdf(self) -> None:
        result = self.classify("document.pdf", b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF")
        self.assertEqual(result["classification"]["detected_type"], "pdf")
        self.assertEqual(result["classification"]["mime_type"], "application/pdf")
        self.assertFalse(result["classification"]["extension_mismatch"])

    def test_plain_text(self) -> None:
        result = self.classify("notes.txt", b"Harmless FileGuard test text.\n")
        self.assertEqual(result["classification"]["detected_type"], "text")
        self.assertFalse(result["classification"]["extension_mismatch"])

    def test_zip_archive(self) -> None:
        sample = self.directory / "files.zip"
        with zipfile.ZipFile(sample, "w") as archive:
            archive.writestr("readme.txt", "harmless")
        result = classify_file(sample)
        self.assertEqual(result["classification"]["detected_type"], "archive")
        self.assertTrue(result["classification"]["is_archive"])

    def test_misleading_extension(self) -> None:
        content = bytearray(132)
        content[:2] = b"MZ"
        content[60:64] = (128).to_bytes(4, "little")
        content[128:132] = b"PE\x00\x00"
        result = self.classify("invoice.pdf", bytes(content))
        self.assertEqual(result["classification"]["detected_type"], "pe")
        self.assertTrue(result["classification"]["extension_mismatch"])

    def test_empty_file(self) -> None:
        result = self.classify("empty", b"")
        self.assertEqual(result["classification"]["detected_type"], "unknown")
        self.assertEqual(result["sample"]["size_bytes"], 0)

    def test_unknown_binary(self) -> None:
        result = self.classify("sample.bin", b"\x00\x01\x02\x03\x80\x81\xfe\xff")
        self.assertEqual(result["classification"]["detected_type"], "unknown")
        self.assertEqual(len(result["sample"]["hashes"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
