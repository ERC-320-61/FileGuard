"""Tests for the Strelka-to-FileGuard evidence adapter."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

from normalizers.strelka import normalize_strelka


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "strelka" / "image.jpg.json"
SCHEMA = ROOT / "schemas" / "static-evidence.schema.json"


class StrelkaNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.original = deepcopy(self.raw)
        self.result = normalize_strelka(self.raw)

    def test_expected_evidence_is_preserved(self) -> None:
        self.assertFalse(self.result["clamav"]["detected"])
        self.assertEqual(self.result["clamav"]["signatures"], [])
        self.assertEqual(self.result["clamav"]["engine_version"], "1.4.2")
        self.assertEqual(self.result["yara"]["matches"], ["test"])
        self.assertEqual(self.result["entropy"]["value"], 7.95227365276721)
        self.assertEqual(self.result["entropy"]["severity"], "informational")
        self.assertEqual(self.result["hashes"]["sha256"], self.raw["scan"]["hash"]["sha256"])

    def test_yara_load_warning_marks_result_incomplete(self) -> None:
        self.assertEqual(self.result["status"], "incomplete")
        self.assertEqual(self.result["yara"]["status"], "incomplete")
        self.assertEqual(self.result["yara"]["flags"], self.raw["scan"]["yara"]["flags"])
        self.assertEqual(self.result["yara"]["warnings"][0]["code"], self.raw["scan"]["yara"]["flags"][0])
        self.assertEqual(self.result["yara"]["errors"], [])

    def test_large_scanner_specific_data_is_not_copied(self) -> None:
        rendered = json.dumps(self.result)
        self.assertNotIn("\"EXIF\"", rendered)
        self.assertNotIn("metadata not copied", rendered)
        self.assertNotIn("omitted from normalized evidence", rendered)

    def test_raw_input_is_not_modified(self) -> None:
        self.assertEqual(self.raw, self.original)

    def test_output_validates_against_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.result)


class ClamavSignatureTests(unittest.TestCase):
    def _normalize_clamav(self, clam_raw: dict) -> dict:
        raw = {
            "file": {"name": "signature-test", "scanners": ["ScanClamav"], "tree": {"root": "req-signature-test"}},
            "scan": {"clamav": clam_raw},
        }
        return normalize_strelka(raw)["clamav"]

    def test_clean_result_has_no_signatures(self) -> None:
        result = self._normalize_clamav(
            {"Infected files": "0", "Engine version": "1.5.3", "Scanned files": "1"}
        )

        self.assertFalse(result["detected"])
        self.assertEqual(result["signatures"], [])

    def test_single_detection_is_captured(self) -> None:
        result = self._normalize_clamav(
            {
                "Infected files": "1",
                "Engine version": "1.5.3",
                "/tmp/tmp36z_d9lb": "Eicar-Test-Signature FOUND",
            }
        )

        self.assertTrue(result["detected"])
        self.assertEqual(result["signatures"], ["Eicar-Test-Signature"])

    def test_duplicate_signatures_are_deduplicated_preserving_order(self) -> None:
        result = self._normalize_clamav(
            {
                "Infected files": "3",
                "Engine version": "1.5.3",
                "/tmp/child-1": "Eicar-Test-Signature FOUND",
                "/tmp/child-2": "Another-Signature FOUND",
                "/tmp/child-3": "Eicar-Test-Signature FOUND",
            }
        )

        self.assertEqual(result["signatures"], ["Eicar-Test-Signature", "Another-Signature"])

    def test_normal_metadata_is_not_mistaken_for_a_signature(self) -> None:
        result = self._normalize_clamav(
            {
                "Data read": "44 B (ratio 2.00",
                "Data scanned": "88 B",
                "End Date": "2026",
                "Engine version": "1.5.3",
                "Infected files": "0",
                "Known viruses": "3628027",
                "Scanned directories": "0",
                "Scanned files": "1",
                "Start Date": "2026",
                "Time": "6.369 sec (0 m 6 s)",
                "elapsed": 6.433434,
            }
        )

        self.assertEqual(result["signatures"], [])

    def test_signatures_validate_against_schema(self) -> None:
        raw = {
            "file": {"name": "signature-schema-test", "scanners": ["ScanClamav"], "tree": {"root": "req-signature-schema-test"}},
            "scan": {
                "clamav": {
                    "Infected files": "1",
                    "Engine version": "1.5.3",
                    "/tmp/tmp36z_d9lb": "Eicar-Test-Signature FOUND",
                },
                "hash": {
                    "md5": "c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4",
                    "sha1": "c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4",
                    "sha256": "c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4c2c4",
                    "ssdeep": "3:eicar-signature-test:eicar-signature-test",
                    "tlsh": "T1EICAR0SIGNATURE0SCHEMA0TEST0PLACEHOLDER0ONLY0NOT0REAL000000",
                },
            },
        }
        evidence = normalize_strelka(raw)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(evidence)


if __name__ == "__main__":
    unittest.main()
