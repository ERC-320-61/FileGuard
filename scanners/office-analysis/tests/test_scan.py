"""Harmless tests for the FileGuard Office Analysis wrapper."""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import scan


CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>
"""

RELATIONSHIPS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="https://example.invalid/harmless" TargetMode="External"/>
</Relationships>
"""


class FakeVBAParser:
    def __init__(self, _path):
        self.closed = False

    def detect_vba_macros(self):
        return True

    def analyze_macros(self):
        return [
            ("AutoExec", "Document_Open", "Runs when the document opens"),
            ("Suspicious", "Shell", "May execute a command"),
        ]

    def close(self):
        self.closed = True


class OfficeWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def make_docx(self, name="document.docx", embedded=False) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("[Content_Types].xml", CONTENT_TYPES)
            archive.writestr("word/document.xml", "<document/>")
            archive.writestr("word/_rels/document.xml.rels", RELATIONSHIPS)
            if embedded:
                archive.writestr("word/embeddings/oleObject1.bin", b"benign object")
        return path

    @patch.object(scan, "_require_tools")
    @patch.object(scan, "detect_encryption", return_value=False)
    @patch.object(scan, "analyze_vba", return_value=(False, []))
    def test_normal_office_document(self, _vba, _encryption, _tools) -> None:
        result = scan.scan_file(self.make_docx())
        self.assertTrue(result["analyzed"])
        self.assertEqual(result["document_type"], "docx")
        self.assertEqual(
            result["external_links"][0]["target"],
            "https://example.invalid/harmless",
        )

    def test_macro_findings(self) -> None:
        with patch.object(scan, "VBA_Parser", FakeVBAParser):
            has_macros, findings = scan.analyze_vba(self.make_docx("macro.docm"))
        self.assertTrue(has_macros)
        self.assertEqual(findings[0]["keyword"], "Document_Open")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[1]["severity"], "medium")

    @patch.object(scan, "_require_tools")
    @patch.object(scan, "detect_encryption", return_value=False)
    @patch.object(scan, "analyze_vba", return_value=(False, []))
    def test_no_macros(self, _vba, _encryption, _tools) -> None:
        result = scan.scan_file(self.make_docx("clean.docx"))
        self.assertFalse(result["has_macros"])
        self.assertEqual(result["macro_findings"], [])

    def test_embedded_object_parsing(self) -> None:
        objects = scan.find_embedded_objects(self.make_docx(embedded=True))
        self.assertEqual(
            objects,
            [{"path": "word/embeddings/oleObject1.bin", "container": "ooxml"}],
        )

    @patch.object(scan, "_require_tools")
    def test_unsupported_file(self, _tools) -> None:
        sample = self.root / "plain.txt"
        sample.write_text("harmless text", encoding="utf-8")
        with self.assertRaises(scan.UnsupportedOfficeFileError):
            scan.scan_file(sample)

    @patch.object(scan, "_require_tools")
    @patch.object(scan, "detect_encryption", return_value=False)
    @patch.object(
        scan,
        "analyze_vba",
        side_effect=scan.OfficeScannerError("olevba failed"),
    )
    def test_scanner_failure(self, _vba, _encryption, _tools) -> None:
        with self.assertRaisesRegex(scan.OfficeScannerError, "olevba failed"):
            scan.scan_file(self.make_docx())


if __name__ == "__main__":
    unittest.main()
