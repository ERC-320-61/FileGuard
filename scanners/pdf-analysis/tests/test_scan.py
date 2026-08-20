"""Harmless unit tests for the FileGuard PDF Analysis wrapper."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import scan


class FakePasswordError(Exception):
    pass


class FakePdfError(Exception):
    pass


class FakePDF:
    pdf_version = "1.7"
    objects = [object(), object(), object()]

    def get_warnings(self):
        return []

    def close(self):
        pass


class FakeEmbeddedDocument:
    def __init__(self, content=b"benign child"):
        self.content = content

    def embfile_names(self):
        return ["../child.txt"]

    def embfile_get(self, _name):
        return self.content

    def embfile_info(self, _name):
        return {"xref": 12}


class PDFWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.sample = self.root / "sample.pdf"
        self.sample.write_bytes(b"%PDF-1.7\n/JS /Launch /OpenAction\n%%EOF")
        self.output = self.root / "children"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def default_document_result(self):
        return {
            "page_count": 1,
            "metadata": {"title": "Harmless PDF"},
            "urls": [],
            "embedded_files": [],
            "children": [],
            "repaired": False,
        }

    def run_success(
        self,
        javascript=None,
        actions=None,
        document_result=None,
        tool_outputs=None,
    ):
        fake_pikepdf = SimpleNamespace(
            open=lambda _path: FakePDF(),
            PasswordError=FakePasswordError,
            PdfError=FakePdfError,
            __version__="10.12.0",
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(scan, "_require_tools"))
            stack.enter_context(patch.object(scan, "pikepdf", fake_pikepdf))
            stack.enter_context(
                patch.object(
                    scan,
                    "_walk_pdf_objects",
                    return_value=(javascript or [], actions or []),
                )
            )
            stack.enter_context(
                patch.object(
                    scan,
                    "_pymupdf_analysis",
                    return_value=document_result or self.default_document_result(),
                )
            )
            stack.enter_context(
                patch.object(
                    scan,
                    "_run_tool",
                    side_effect=tool_outputs or ["/JS 1\n/Launch 1", "stats"],
                )
            )
            stack.enter_context(
                patch.object(scan, "fitz", SimpleNamespace(VersionBind="1.28.2"))
            )
            return scan.scan_file(self.sample, self.output)

    def test_normal_pdf(self) -> None:
        result = self.run_success()
        self.assertTrue(result["analyzed"])
        self.assertEqual(result["pdf_version"], "1.7")
        self.assertEqual(result["page_count"], 1)
        self.assertEqual(result["object_count"], 3)

    def test_metadata_extraction(self) -> None:
        result = self.run_success()
        self.assertEqual(result["metadata"]["title"], "Harmless PDF")

    def test_javascript_indicator_and_content(self) -> None:
        javascript = [
            {
                "object_ref": "4 0 R",
                "key": "/JS",
                "path": "/OpenAction/JS",
                "content": "app.alert('harmless')",
            }
        ]
        result = self.run_success(javascript=javascript)
        self.assertEqual(result["javascript"][0]["content"], "app.alert('harmless')")

    def test_url_extraction(self) -> None:
        document = self.default_document_result()
        document["urls"] = [
            {
                "page": 1,
                "uri": "https://example.invalid",
                "file": None,
                "kind": 2,
                "xref": 7,
            }
        ]
        result = self.run_success(document_result=document)
        self.assertEqual(result["urls"][0]["uri"], "https://example.invalid")

    def test_launch_action(self) -> None:
        result = self.run_success(
            actions=[{"type": "Launch", "object_ref": "5 0 R", "path": "/Launch"}]
        )
        self.assertEqual(result["actions"][0]["type"], "Launch")

    def test_open_action(self) -> None:
        result = self.run_success(
            actions=[
                {"type": "OpenAction", "object_ref": "1 0 R", "path": "/OpenAction"}
            ]
        )
        self.assertEqual(result["actions"][0]["type"], "OpenAction")

    def test_suspicious_pdf_keywords(self) -> None:
        indicators = scan._token_indicators(
            b"%PDF-1.7 /JavaScript /AA /ObjStm /XFA", {}
        )
        names = {item["indicator"] for item in indicators}
        self.assertTrue({"/JavaScript", "/AA", "/ObjStm", "/XFA"} <= names)

    def test_embedded_file_detection(self) -> None:
        document = self.default_document_result()
        document["embedded_files"] = [{"name": "child.txt", "info": {"xref": 12}}]
        result = self.run_success(document_result=document)
        self.assertEqual(result["embedded_files"][0]["name"], "child.txt")

    def test_child_extraction_and_sha256(self) -> None:
        content = b"benign embedded child"
        children = scan._extract_children(FakeEmbeddedDocument(content), self.output)
        self.assertEqual(children[0]["original_name"], "../child.txt")
        self.assertEqual(children[0]["output_path"], str(self.output / "000-child.txt"))
        self.assertEqual(children[0]["size"], len(content))
        self.assertEqual(children[0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual((self.output / "000-child.txt").read_bytes(), content)

    def test_encrypted_pdf(self) -> None:
        fake_pikepdf = SimpleNamespace(
            open=lambda _path: (_ for _ in ()).throw(FakePasswordError()),
            PasswordError=FakePasswordError,
            PdfError=FakePdfError,
        )
        with patch.object(scan, "_require_tools"), patch.object(
            scan, "pikepdf", fake_pikepdf
        ):
            with self.assertRaises(scan.EncryptedPDFError):
                scan.scan_file(self.sample, self.output)

    def test_malformed_pdf(self) -> None:
        fake_pikepdf = SimpleNamespace(
            open=lambda _path: (_ for _ in ()).throw(FakePdfError("bad xref")),
            PasswordError=FakePasswordError,
            PdfError=FakePdfError,
        )
        with patch.object(scan, "_require_tools"), patch.object(
            scan, "pikepdf", fake_pikepdf
        ):
            with self.assertRaisesRegex(scan.MalformedPDFError, "bad xref"):
                scan.scan_file(self.sample, self.output)

    def test_unsupported_file(self) -> None:
        unsupported = self.root / "sample.txt"
        unsupported.write_text("not a PDF", encoding="utf-8")
        with patch.object(scan, "_require_tools"):
            with self.assertRaises(scan.UnsupportedPDFError):
                scan.scan_file(unsupported, self.output)

    def test_scanner_tool_failure(self) -> None:
        with self.assertRaisesRegex(scan.PDFToolError, "pdfid.py failed"):
            with patch.object(
                scan.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=2, stdout="", stderr="synthetic tool failure"
                ),
            ):
                scan._run_tool([scan.sys.executable, "pdfid.py"], 1)


if __name__ == "__main__":
    unittest.main()
