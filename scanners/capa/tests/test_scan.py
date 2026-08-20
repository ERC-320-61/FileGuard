"""Unit tests for the FileGuard capa wrapper."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanners.capa.scripts.scan import (
    CapaScannerError,
    UnsupportedFileError,
    normalize_capabilities,
    parse_capa_document,
    scan_file,
)


def completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class CapaWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.sample = Path(self.temporary_directory.name) / "benign.exe"
        self.sample.write_bytes(b"MZ harmless test fixture")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def document(self):
        return {
            "meta": {
                "version": "9.4.0",
                "analysis": {"ruleset_version": "2026-08-test"},
            },
            "rules": {
                "create or open file": {
                    "meta": {
                        "name": "create or open file",
                        "namespace": "file-system/file-operations",
                        "category": ["file"],
                        "att&ck": [
                            "Discovery::File and Directory Discovery [T1083]"
                        ],
                    },
                    "matches": [],
                }
            },
        }

    @patch("scanners.capa.scripts.scan._run")
    def test_successful_analysis(self, run) -> None:
        run.side_effect = [
            completed(0, "capa v9.4.0"),
            completed(0, json.dumps(self.document())),
        ]
        result = scan_file(self.sample)
        self.assertTrue(result["analyzed"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["engine_version"], "9.4.0")

    def test_capability_parsing(self) -> None:
        capabilities, _ = normalize_capabilities(self.document())
        self.assertEqual(capabilities[0]["name"], "create or open file")
        self.assertEqual(
            capabilities[0]["namespace"], "file-system/file-operations"
        )
        self.assertEqual(capabilities[0]["categories"], ["file"])

    def test_attack_metadata_parsing(self) -> None:
        _, attack = normalize_capabilities(self.document())
        self.assertEqual(attack[0]["id"], "T1083")
        self.assertIn("File and Directory Discovery", attack[0]["name"])

    def test_no_capabilities(self) -> None:
        document = {
            "meta": {"version": "9.4.0", "analysis": {"rules": ["default"]}},
            "rules": {},
        }
        result = parse_capa_document(document, "9.4.0")
        self.assertTrue(result["analyzed"])
        self.assertEqual(result["capabilities"], [])
        self.assertEqual(result["attack_mappings"], [])

    def test_internal_library_rules_are_not_capabilities(self) -> None:
        document = {
            "rules": {
                "internal helper": {
                    "meta": {"name": "internal helper", "lib": True}
                }
            }
        }
        capabilities, attack = normalize_capabilities(document)
        self.assertEqual(capabilities, [])
        self.assertEqual(attack, [])

    @patch("scanners.capa.scripts.scan._run")
    def test_unsupported_file(self, run) -> None:
        run.side_effect = [
            completed(0, "capa v9.4.0"),
            completed(16, stderr="input file does not appear to be a supported file"),
        ]
        with self.assertRaises(UnsupportedFileError):
            scan_file(self.sample)

    @patch("scanners.capa.scripts.scan._run")
    def test_scanner_failure(self, run) -> None:
        run.side_effect = [
            completed(0, "capa v9.4.0"),
            completed(2, stderr="rules could not be loaded"),
        ]
        with self.assertRaisesRegex(CapaScannerError, "rules could not be loaded"):
            scan_file(self.sample)


if __name__ == "__main__":
    unittest.main()
