"""Local OPA integration tests for the first FileGuard disposition policy."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from normalizers.strelka import normalize_strelka


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "fileguard" / "disposition.rego"
FIXTURE = ROOT / "tests" / "fixtures" / "strelka" / "image.jpg.json"
CLEAN_FIXTURE = ROOT / "tests" / "fixtures" / "fileguard" / "static-evidence.clean.json"
SUSPICIOUS_FIXTURE = ROOT / "tests" / "fixtures" / "fileguard" / "static-evidence.suspicious.json"
MALICIOUS_FIXTURE = ROOT / "tests" / "fixtures" / "fileguard" / "static-evidence.malicious.json"
OPA = shutil.which("opa")


@unittest.skipUnless(
    OPA,
    "OPA integration tests skipped: install the 'opa' executable and add it to PATH",
)
class FileGuardPolicyTests(unittest.TestCase):
    def evaluate(self, evidence: dict) -> dict:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "evidence.json"
            input_path.write_text(json.dumps(evidence), encoding="utf-8")
            process = subprocess.run(
                [
                    OPA,
                    "eval",
                    "--format=json",
                    "--data",
                    str(POLICY),
                    "--input",
                    str(input_path),
                    "data.fileguard.disposition.decision",
                ],
                capture_output=True,
                check=False,
                text=True,
            )

        if process.returncode != 0:
            self.fail(f"OPA evaluation failed:\n{process.stderr or process.stdout}")

        result = json.loads(process.stdout)
        return result["result"][0]["expressions"][0]["value"]

    def normalized_fixture(self) -> dict:
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        return normalize_strelka(raw)
    def clean_fixture(self) -> dict:
        return json.loads(CLEAN_FIXTURE.read_text(encoding="utf-8"))

    def suspicious_fixture(self) -> dict:
        return json.loads(SUSPICIOUS_FIXTURE.read_text(encoding="utf-8"))

    def malicious_fixture(self) -> dict:
        return json.loads(MALICIOUS_FIXTURE.read_text(encoding="utf-8"))

    def test_incomplete_normalized_strelka_evidence_is_quarantined(self) -> None:
        decision = self.evaluate(self.normalized_fixture())

        self.assertEqual(decision["conclusion"], "INCOMPLETE")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])
        self.assertEqual(
            decision["reasons"],
            ["Normalized static evidence is incomplete."],
        )

    def test_unmatched_evidence_fails_closed(self) -> None:
        evidence = self.normalized_fixture()
        evidence["status"] = "complete"

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "INCOMPLETE")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])
        self.assertEqual(
            decision["reasons"],
            ["No disposition rule matched; quarantined by default."],
        )

    def test_qualifying_evidence_is_clean(self) -> None:
        decision = self.evaluate(self.clean_fixture())

        self.assertEqual(decision["conclusion"], "CLEAN")
        self.assertEqual(decision["destination"], "clean")
        self.assertFalse(decision["review_required"])
        self.assertEqual(
            decision["reasons"],
            ["Required static analysis completed with no blocking findings."],
        )

    def test_warning_prevents_clean(self) -> None:
        evidence = self.clean_fixture()
        evidence["warnings"].append(
            {"scanner": "yara", "code": "configuration_warning"}
        )

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "INCOMPLETE")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])

    def test_scanner_incomplete_state_prevents_clean(self) -> None:
        evidence = self.clean_fixture()
        evidence["yara"]["status"] = "incomplete"

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "INCOMPLETE")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])

    def test_clamav_detection_is_malicious(self) -> None:
        decision = self.evaluate(self.malicious_fixture())

        self.assertEqual(decision["conclusion"], "MALICIOUS")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])
        self.assertEqual(decision["reasons"], ["ClamAV detected malware."])

    def test_yara_match_without_clamav_detection_is_suspicious(self) -> None:
        decision = self.evaluate(self.suspicious_fixture())

        self.assertEqual(decision["conclusion"], "SUSPICIOUS")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])
        self.assertEqual(
            decision["reasons"],
            ["YARA matched one or more rules with no stronger malware detection."],
        )

    def test_clamav_detection_outranks_yara_match(self) -> None:
        evidence = self.malicious_fixture()
        evidence["yara"]["matches"] = ["Test_Suspicious_Indicator"]

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "MALICIOUS")

    def test_clamav_detection_outranks_incomplete_status(self) -> None:
        evidence = self.malicious_fixture()
        evidence["status"] = "incomplete"

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "MALICIOUS")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])

    def test_incomplete_status_with_yara_match_is_incomplete_not_suspicious(self) -> None:
        evidence = self.suspicious_fixture()
        evidence["status"] = "incomplete"

        decision = self.evaluate(evidence)

        self.assertEqual(decision["conclusion"], "INCOMPLETE")
        self.assertEqual(decision["destination"], "quarantine")
        self.assertTrue(decision["review_required"])

if __name__ == "__main__":
    unittest.main()
