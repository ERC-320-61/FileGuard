"""Tests for the FileGuard end-to-end static disposition pipeline."""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from pipeline import PipelineError, run_pipeline


ROOT = Path(__file__).resolve().parents[1]
CLEAN_WRAPPER_FIXTURE = ROOT / "tests" / "fixtures" / "strelka" / "fileguard-clean-test.wrapper.json"
INCOMPLETE_WRAPPER_FIXTURE = ROOT / "tests" / "fixtures" / "strelka" / "image.jpg.real.json"
OPA = shutil.which("opa")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class PipelineFailClosedTests(unittest.TestCase):
    def test_malformed_wrapper_is_extraction_failure(self) -> None:
        with self.assertRaises(PipelineError) as ctx:
            run_pipeline({"file_name": "not-a-strelka-wrapper.txt"})

        self.assertEqual(ctx.exception.stage, "extraction")


@unittest.skipUnless(
    OPA,
    "OPA-dependent pipeline tests skipped: install the 'opa' executable and add it to PATH",
)
class PipelineOpaTests(unittest.TestCase):
    def test_real_clean_wrapper_produces_clean(self) -> None:
        wrapper = _load(CLEAN_WRAPPER_FIXTURE)

        result = run_pipeline(wrapper)

        self.assertIn("static_evidence", result)
        self.assertIn("opa_decision", result)
        self.assertEqual(result["static_evidence"]["status"], "complete")
        self.assertEqual(result["opa_decision"]["conclusion"], "CLEAN")
        self.assertEqual(result["opa_decision"]["destination"], "clean")
        self.assertFalse(result["opa_decision"]["review_required"])

    def test_incomplete_wrapper_produces_incomplete(self) -> None:
        wrapper = _load(INCOMPLETE_WRAPPER_FIXTURE)

        result = run_pipeline(wrapper)

        self.assertEqual(result["static_evidence"]["status"], "incomplete")
        self.assertEqual(result["opa_decision"]["conclusion"], "INCOMPLETE")
        self.assertEqual(result["opa_decision"]["destination"], "quarantine")
        self.assertTrue(result["opa_decision"]["review_required"])


if __name__ == "__main__":
    unittest.main()
