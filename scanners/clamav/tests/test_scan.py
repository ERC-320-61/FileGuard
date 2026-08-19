"""Unit tests for the FileGuard ClamAV wrapper."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanners.clamav.scripts.scan import (
    parse_clamav_version,
    parse_detection,
    scan_file,
)


class ClamAVWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.sample = Path(self.temporary_directory.name) / "sample.txt"
        self.sample.write_text("harmless test file", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_version_parser(self) -> None:
        self.assertEqual(
            parse_clamav_version("ClamAV 1.4.3/27562/Mon Jan 01 00:00:00 2026"),
            ("1.4.3", "27562"),
        )

    def test_detection_parser(self) -> None:
        output = "/samples/eicar.com.txt: Win.Test.EICAR_HDB-1 FOUND\n"
        self.assertEqual(parse_detection(output), "Win.Test.EICAR_HDB-1")

    @patch("scanners.clamav.scripts.scan.subprocess.run")
    def test_clean_result(self, run) -> None:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "ClamAV 1.4.3/27562/date\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
        result = scan_file(self.sample)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["detected"])
        self.assertIsNone(result["signature"])

    @patch("scanners.clamav.scripts.scan.subprocess.run")
    def test_eicar_detection_result(self, run) -> None:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "ClamAV 1.4.3/27562/date\n", ""),
            subprocess.CompletedProcess(
                [], 1, f"{self.sample}: Win.Test.EICAR_HDB-1 FOUND\n", ""
            ),
        ]
        result = scan_file(self.sample)
        self.assertTrue(result["detected"])
        self.assertEqual(result["signature"], "Win.Test.EICAR_HDB-1")

    @patch("scanners.clamav.scripts.scan.subprocess.run")
    def test_scanner_failure_is_not_clean(self, run) -> None:
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "ClamAV 1.4.3/27562/date\n", ""),
            subprocess.CompletedProcess([], 2, "", "database unavailable"),
        ]
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            scan_file(self.sample)

    def test_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scan_file(self.sample.with_name("missing.bin"))


if __name__ == "__main__":
    unittest.main()
