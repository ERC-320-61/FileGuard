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


if __name__ == "__main__":
    unittest.main()
