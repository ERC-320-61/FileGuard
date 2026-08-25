"""Tests for the CAPE-to-FileGuard dynamic evidence adapter."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

from normalizers.cape import normalize_cape


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "dynamic-evidence.schema.json"

# Small representative fixture, not a full real CAPE report. Top-level keys
# mirror the real ones a CAPE report was observed to return (statistics,
# target, procdump, dropped, CAPE, info, behavior, debug, network,
# signatures, malscore, ttps, malstatus) -- only the keys normalize_cape()
# actually reads are populated with meaningful data; the rest are present
# but empty/minimal, exercising that the normalizer ignores them.
REPRESENTATIVE_REPORT = {
    "statistics": {"processing": []},
    "info": {
        "id": 3,
        "duration": 60,
        "started": "2026-08-24 00:00:00",
        "ended": "2026-08-24 00:01:00",
    },
    "target": {
        "category": "file",
        "file": {
            "name": "fileguard-cape-behavioral-test.ps1",
            "size": 512,
            "type": "ASCII text",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
        },
    },
    "behavior": {
        "processes": [
            {"process_id": 100, "process_name": "fileguard-cape-behavioral-test.ps1", "parent_id": 1},
            {"process_id": 101, "process_name": "powershell.exe", "parent_id": 100},
            {"process_id": 102, "process_name": "cmd.exe", "parent_id": 101},
            {"process_id": 103, "process_name": "conhost.exe", "parent_id": 102},
            {"process_id": 104, "process_name": "notepad.exe", "parent_id": 101},
        ],
        "processtree": [
            {
                "process_id": 100,
                "process_name": "fileguard-cape-behavioral-test.ps1",
                "children": [{"process_id": 101, "process_name": "powershell.exe", "children": []}],
            }
        ],
    },
    "procdump": [],
    "dropped": [],
    "CAPE": [],
    "debug": {"log": [], "errors": []},
    "network": {"hosts": [], "domains": [], "dns": []},
    "signatures": [
        {
            "name": "creates_process",
            "severity": 1,
            "description": "Creates a new process.",
            "ttps": ["T1059.001"],
        },
        {
            "name": "writes_registry",
            "severity": 2,
            "description": "Writes a registry value.",
            # Shares T1059.001 with the signature above and adds a second ID --
            # exercises both cross-signature dedup and multi-TTP-per-signature.
            "ttps": ["T1112", "T1059.001"],
        },
        {
            "name": "hardware_id_profiling",
            "severity": 1,
            "description": "Queries hardware identifiers.",
            "ttps": [],
        },
    ],
    "malscore": 0.0,
    "malstatus": None,
    # Real CAPE reports have been observed to carry signature *names* here,
    # not MITRE ATT&CK IDs -- this must never be read as a TTP source.
    "ttps": ["hardware_id_profiling", "creates_process"],
}


class CapeNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = deepcopy(REPRESENTATIVE_REPORT)
        self.original = deepcopy(self.raw)
        self.result = normalize_cape(self.raw)

    def test_normalizes_successfully(self) -> None:
        self.assertEqual(self.result["schema_version"], "1.0")
        self.assertEqual(self.result["source"], {"engine": "cape"})

    def test_process_count_derived_from_behavior_processes(self) -> None:
        self.assertEqual(self.result["behavior"]["process_count"], 5)

    def test_process_tree_count_derived_from_behavior_processtree(self) -> None:
        self.assertEqual(self.result["behavior"]["process_tree_count"], 1)

    def test_process_names_extracted_deterministically(self) -> None:
        self.assertEqual(
            self.result["behavior"]["process_names"],
            [
                "fileguard-cape-behavioral-test.ps1",
                "powershell.exe",
                "cmd.exe",
                "conhost.exe",
                "notepad.exe",
            ],
        )

    def test_malscore_preserved_without_verdict_conversion(self) -> None:
        self.assertEqual(self.result["analysis"]["score"], 0.0)
        rendered = json.dumps(self.result)
        for forbidden in ("verdict", "conclusion", "CLEAN", "SUSPICIOUS", "MALICIOUS"):
            self.assertNotIn(forbidden, rendered)

    def test_signatures_are_normalized(self) -> None:
        self.assertEqual(
            self.result["signatures"],
            [
                {"name": "creates_process", "severity": 1, "description": "Creates a new process."},
                {"name": "writes_registry", "severity": 2, "description": "Writes a registry value."},
                {"name": "hardware_id_profiling", "severity": 1, "description": "Queries hardware identifiers."},
            ],
        )

    def test_ttps_derived_from_signature_ttps_deduplicated_and_sorted(self) -> None:
        # T1059.001 appears on two signatures and must only appear once; the
        # bad top-level report["ttps"] (signature names) must be ignored
        # entirely -- neither "hardware_id_profiling" nor "creates_process"
        # may appear.
        self.assertEqual(self.result["ttps"], ["T1059.001", "T1112"])

    def test_no_null_or_signature_name_ttp_ids(self) -> None:
        for value in self.result["ttps"]:
            self.assertIsNotNone(value)
            self.assertNotIn(value, ("hardware_id_profiling", "creates_process", "writes_registry"))

    def test_target_fields_normalized_when_available(self) -> None:
        self.assertEqual(
            self.result["target"],
            {
                "name": "fileguard-cape-behavioral-test.ps1",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "size": 512,
                "type": "ASCII text",
            },
        )

    def test_analysis_fields_normalized_when_available(self) -> None:
        self.assertEqual(
            self.result["analysis"],
            {"task_id": 3, "duration_seconds": 60, "score": 0.0, "malstatus": None},
        )

    def test_raw_input_is_not_modified(self) -> None:
        self.assertEqual(self.raw, self.original)

    def test_output_validates_against_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.result)


class CapeTtpNormalizationTests(unittest.TestCase):
    """Focused, isolated coverage of TTP extraction from signature['ttps']."""

    def test_signature_with_single_ttp_id(self) -> None:
        result = normalize_cape({"signatures": [{"name": "sig1", "ttps": ["T1082"]}]})
        self.assertEqual(result["ttps"], ["T1082"])

    def test_multiple_signatures_sharing_same_ttp_id(self) -> None:
        result = normalize_cape(
            {
                "signatures": [
                    {"name": "sig1", "ttps": ["T1082"]},
                    {"name": "sig2", "ttps": ["T1082"]},
                ]
            }
        )
        self.assertEqual(result["ttps"], ["T1082"])

    def test_signature_with_multiple_ttp_ids(self) -> None:
        result = normalize_cape({"signatures": [{"name": "sig1", "ttps": ["T1082", "T1012", "T1059.001"]}]})
        self.assertEqual(result["ttps"], ["T1012", "T1059.001", "T1082"])

    def test_missing_ttps_on_signature_yields_no_ttps(self) -> None:
        result = normalize_cape({"signatures": [{"name": "sig1", "severity": 1, "description": "d"}]})
        self.assertEqual(result["ttps"], [])

    def test_missing_signatures_entirely_yields_no_ttps(self) -> None:
        result = normalize_cape({"malscore": 1.0})
        self.assertEqual(result["ttps"], [])

    def test_malformed_ttps_entries_are_rejected_not_crashed(self) -> None:
        result = normalize_cape(
            {
                "signatures": [
                    {
                        "name": "sig1",
                        "ttps": [
                            "hardware_id_profiling",  # a signature name, not an ATT&CK ID
                            "not-a-real-id",
                            123,
                            None,
                            {"unexpected": "shape"},
                            "T1082",  # the only genuinely valid entry
                        ],
                    }
                ]
            }
        )
        self.assertEqual(result["ttps"], ["T1082"])

    def test_ttps_dict_entries_with_valid_id_field_are_accepted(self) -> None:
        result = normalize_cape({"signatures": [{"name": "sig1", "ttps": [{"ttp": "T1082"}]}]})
        self.assertEqual(result["ttps"], ["T1082"])

    def test_deduplication_is_deterministic_regardless_of_source_order(self) -> None:
        report_a = {"signatures": [{"ttps": ["T1112", "T1082"]}, {"ttps": ["T1082"]}]}
        report_b = {"signatures": [{"ttps": ["T1082"]}, {"ttps": ["T1082", "T1112"]}]}

        self.assertEqual(normalize_cape(report_a)["ttps"], normalize_cape(report_b)["ttps"])
        self.assertEqual(normalize_cape(report_a)["ttps"], ["T1082", "T1112"])

    def test_no_ttp_entry_is_ever_null(self) -> None:
        result = normalize_cape(
            {"signatures": [{"ttps": ["T1082", "not-valid", None]}]}
        )
        self.assertTrue(all(value is not None for value in result["ttps"]))

    def test_top_level_report_ttps_field_is_never_used(self) -> None:
        # Real CAPE reports have carried signature names under the top-level
        # "ttps" key -- it must be ignored entirely, even when signatures
        # themselves contribute nothing.
        result = normalize_cape({"ttps": ["hardware_id_profiling", "T1082"], "signatures": []})
        self.assertEqual(result["ttps"], [])


class CapeNormalizerMissingFieldsTests(unittest.TestCase):
    def test_missing_optional_sections_do_not_crash(self) -> None:
        result = normalize_cape({"info": {"id": 5}})

        self.assertEqual(result["behavior"], {"process_count": 0, "process_tree_count": 0, "process_names": []})
        self.assertEqual(result["signatures"], [])
        self.assertEqual(result["ttps"], [])
        self.assertEqual(result["target"], {"name": None, "sha256": None, "md5": None, "size": None, "type": None})
        self.assertEqual(result["analysis"]["task_id"], 5)
        self.assertIsNone(result["analysis"]["duration_seconds"])
        self.assertIsNone(result["analysis"]["score"])
        self.assertIsNone(result["analysis"]["malstatus"])

    def test_empty_report_normalizes_without_error(self) -> None:
        result = normalize_cape({})

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)

    def test_malformed_signature_entries_are_skipped_not_crashed(self) -> None:
        result = normalize_cape({"signatures": ["not-a-dict", None, {"name": "ok", "severity": 1, "description": "d"}]})

        self.assertEqual(result["signatures"], [{"name": "ok", "severity": 1, "description": "d"}])

    def test_non_dict_input_raises_value_error(self) -> None:
        for bad_input in ("not a report", ["a", "list"], None, 42):
            with self.assertRaises(ValueError):
                normalize_cape(bad_input)


if __name__ == "__main__":
    unittest.main()
