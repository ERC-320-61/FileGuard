"""Unit tests for the FileGuard YARA wrapper."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanners.yara.scripts.scan import normalize_match, scan_file


class FakeMatch:
    def __init__(self, rule: str, namespace: str = "internal_test", meta=None):
        self.rule = rule
        self.namespace = namespace
        self.meta = meta or {}


class FakeRules:
    def __init__(self, matches=None, error: Exception | None = None):
        self.matches = matches or []
        self.error = error

    def match(self, **_kwargs):
        if self.error:
            raise self.error
        return self.matches


class YaraWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(b"harmless")
        self.rules_root = self.root / "rules"
        self.rules_root.mkdir()
        self.rule_file = self.rules_root / "test.yar"
        self.rule_file.write_text("rule harmless { condition: false }", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def scan_with(self, matches):
        compiled = FakeRules(matches)
        with patch(
            "scanners.yara.scripts.scan.compile_rules",
            return_value=(compiled, [self.rule_file], self.rules_root),
        ):
            return scan_file(self.sample, self.rules_root)

    def test_no_match(self) -> None:
        result = self.scan_with([])
        self.assertFalse(result["detected"])
        self.assertEqual(result["matched_rules"], [])

    def test_single_match(self) -> None:
        result = self.scan_with([FakeMatch("Harmless_One")])
        self.assertTrue(result["detected"])
        self.assertEqual(result["matched_rules"][0]["name"], "Harmless_One")

    def test_multiple_matches_are_stable(self) -> None:
        result = self.scan_with(
            [
                FakeMatch("Second", "internal_z"),
                FakeMatch("First", "internal_a"),
            ]
        )
        self.assertEqual(
            [item["name"] for item in result["matched_rules"]],
            ["First", "Second"],
        )

    def test_rule_metadata_parsing(self) -> None:
        match = FakeMatch(
            "Metadata_Rule",
            meta={
                "description": b"harmless metadata",
                "severity": "low",
                "confidence": 90,
            },
        )
        normalized = normalize_match(match)
        self.assertEqual(normalized["metadata"]["description"], "harmless metadata")
        self.assertEqual(normalized["severity"], "low")
        self.assertEqual(normalized["confidence"], 90)

    def test_rule_compilation_failure(self) -> None:
        with patch(
            "scanners.yara.scripts.scan.compile_rules",
            side_effect=RuntimeError("invalid rule syntax"),
        ):
            with self.assertRaisesRegex(RuntimeError, "invalid rule syntax"):
                scan_file(self.sample, self.rules_root)

    def test_scanner_failure(self) -> None:
        compiled = FakeRules(error=RuntimeError("scanner failed"))
        with patch(
            "scanners.yara.scripts.scan.compile_rules",
            return_value=(compiled, [self.rule_file], self.rules_root),
        ):
            with self.assertRaisesRegex(RuntimeError, "scanner failed"):
                scan_file(self.sample, self.rules_root)


if __name__ == "__main__":
    unittest.main()
