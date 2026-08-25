"""Normalize raw CAPE reports into FileGuard dynamic evidence.

This is the only place in FileGuard that needs to understand CAPE's raw
report shape. Everything downstream should only ever see the normalized
structure this module produces -- the same separation already used between
Strelka's raw output and normalizers/strelka.py.

This module does not make or imply a disposition decision. `analysis.score`
is CAPE's raw malscore, preserved as-is; it is not interpreted into a
CLEAN/SUSPICIOUS/MALICIOUS verdict here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Standard MITRE ATT&CK technique ID shape: "T" + 4 digits, optionally a
# ".NNN" sub-technique suffix (e.g. "T1059", "T1059.001").
_ATTACK_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _number_or_none(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, (int, float)) else None


def _process_names(processes: list[Any]) -> list[str]:
    return [
        proc["process_name"]
        for proc in processes
        if isinstance(proc, dict) and isinstance(proc.get("process_name"), str)
    ]


def _normalize_signatures(raw_signatures: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": _str_or_none(sig.get("name")),
            "severity": _number_or_none(sig.get("severity")),
            "description": _str_or_none(sig.get("description")),
        }
        for sig in raw_signatures
        if isinstance(sig, dict)
    ]


def _attack_id_or_none(value: Any) -> str | None:
    """Return value if it looks like a real MITRE ATT&CK technique ID.

    This is what prevents CAPE signature names (e.g. "hardware_id_profiling")
    from being mistaken for ATT&CK IDs or descriptions -- a signature name
    never matches the T#### / T####.### shape, so it is silently rejected
    rather than emitted as a fabricated or null TTP.
    """
    if isinstance(value, str) and _ATTACK_ID_PATTERN.match(value):
        return value
    return None


def _normalize_ttps(raw_signatures: list[Any]) -> list[str]:
    """Derive FileGuard's TTP list from each signature's own `ttps` field.

    CAPE signatures carry their MITRE ATT&CK mapping under
    signature["ttps"] (a list of technique ID strings), not under a
    top-level report["ttps"] -- that top-level field has been observed to
    contain CAPE signature names instead of real ATT&CK data, so it is not
    used as a source here. Only entries that look like a real ATT&CK ID are
    kept; nothing is invented. The result is deduplicated and sorted so
    output is deterministic regardless of signature order.
    """
    technique_ids: set[str] = set()
    for sig in raw_signatures:
        if not isinstance(sig, dict):
            continue
        for entry in _list_or_empty(sig.get("ttps")):
            technique_id = None
            if isinstance(entry, str):
                technique_id = _attack_id_or_none(entry)
            elif isinstance(entry, dict):
                technique_id = _attack_id_or_none(entry.get("ttp") or entry.get("id") or entry.get("technique"))
            if technique_id:
                technique_ids.add(technique_id)
    return sorted(technique_ids)


def normalize_cape(report: Any) -> dict[str, Any]:
    """Return normalized FileGuard dynamic evidence for a raw CAPE report."""
    if not isinstance(report, dict):
        raise ValueError("CAPE report must be an object")

    info = _dict_or_empty(report.get("info"))
    target_file = _dict_or_empty(_dict_or_empty(report.get("target")).get("file"))
    behavior = _dict_or_empty(report.get("behavior"))

    processes = _list_or_empty(behavior.get("processes"))
    processtree = _list_or_empty(behavior.get("processtree"))
    signatures = _list_or_empty(report.get("signatures"))

    return {
        "schema_version": "1.0",
        "source": {"engine": "cape"},
        "analysis": {
            "task_id": _int_or_none(info.get("id")),
            "duration_seconds": _number_or_none(info.get("duration")),
            "score": _number_or_none(report.get("malscore")),
            "malstatus": _str_or_none(report.get("malstatus")),
        },
        "target": {
            "name": _str_or_none(target_file.get("name")),
            "sha256": _str_or_none(target_file.get("sha256")),
            "md5": _str_or_none(target_file.get("md5")),
            "size": _int_or_none(target_file.get("size")),
            "type": _str_or_none(target_file.get("type")),
        },
        "behavior": {
            "process_count": len(processes),
            "process_tree_count": len(processtree),
            "process_names": _process_names(processes),
        },
        "signatures": _normalize_signatures(signatures),
        "ttps": _normalize_ttps(signatures),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="Raw CAPE report JSON (defaults to stdin)")
    parser.add_argument("-o", "--output", type=Path, help="Output file (defaults to stdout)")
    args = parser.parse_args(argv)

    if args.input:
        raw = json.loads(args.input.read_text(encoding="utf-8"))
    else:
        raw = json.load(sys.stdin)
    rendered = json.dumps(normalize_cape(raw), indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
