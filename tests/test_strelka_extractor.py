"""Tests for extracting raw events from Strelka UI/API wrappers."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from extractors.strelka_ui import extract_strelka_event
from normalizers.strelka import normalize_strelka


ROOT = Path(__file__).resolve().parents[1]
REAL_WRAPPER_FIXTURE = (
    ROOT / "tests" / "fixtures" / "strelka" / "image.jpg.real.json"
)


class StrelkaExtractorTests(unittest.TestCase):
    def test_valid_wrapper_extraction(self) -> None:
        wrapper = json.loads(REAL_WRAPPER_FIXTURE.read_text(encoding="utf-8"))

        event = extract_strelka_event(wrapper)

        self.assertIs(event, wrapper["strelka_response"][0])
        self.assertIn("file", event)
        self.assertIn("scan", event)
        self.assertEqual(normalize_strelka(event)["file"]["filename"], "image.jpg")

    def test_missing_strelka_response(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing 'strelka_response'"):
            extract_strelka_event({"file_name": "image.jpg"})

    def test_empty_strelka_response(self) -> None:
        with self.assertRaisesRegex(ValueError, "contains no events"):
            extract_strelka_event({"strelka_response": []})

    def test_first_event_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(ValueError, r"strelka_response\[0\].*object"):
            extract_strelka_event({"strelka_response": ["not an event"]})


if __name__ == "__main__":
    unittest.main()
