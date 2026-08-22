"""Normalize raw Strelka scan events into FileGuard static evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any


WARNING_MARKERS = ("warning", "warn", "not_found", "no_rules", "load_error", "compiling_error")
ERROR_MARKERS = ("error", "exception", "timed_out", "timeout")


def _canonical_scanner(name: str) -> str:
    name = re.sub(r"^Scan", "", name)
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _condition(scanner: str, code: str, message: str | None = None) -> dict[str, str]:
    item = {"scanner": scanner, "code": code}
    if message:
        item["message"] = message
    return item


def _classify_conditions(scanner: str, result: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for raw_flag in result.get("flags", []):
        flag = str(raw_flag)
        lowered = flag.lower()
        target = errors if any(marker in lowered for marker in ERROR_MARKERS) else warnings
        # YARA configuration and rule-loading problems are incomplete warnings,
        # even when Strelka includes "error" in the flag text.
        if scanner == "yara" and any(marker in lowered for marker in WARNING_MARKERS):
            target = warnings
        target.append(_condition(scanner, flag))

    if result.get("exception"):
        errors.append(_condition(scanner, "exception", str(result["exception"])))
    return warnings, errors


def _status(warnings: list[Any], errors: list[Any]) -> str:
    if errors:
        return "error"
    if warnings:
        return "incomplete"
    return "complete"


def _event_from_raw(raw: Any) -> dict[str, Any]:
    if isinstance(raw, list):
        if not raw:
            raise ValueError("Strelka result contains no events")
        raw = raw[0]
    if not isinstance(raw, dict) or not isinstance(raw.get("file"), dict):
        raise ValueError("Expected a Strelka event containing a 'file' object")
    return raw


def normalize_strelka(raw: Any) -> dict[str, Any]:
    """Return normalized evidence without mutating the raw Strelka object."""
    event = _event_from_raw(raw)
    file_data = event["file"]
    scan = event.get("scan", {})
    tree = file_data.get("tree", {})

    document_warnings: list[dict[str, str]] = []
    document_errors: list[dict[str, str]] = []

    clam_raw = scan.get("clamav", {})
    clam_warnings, clam_errors = _classify_conditions("clamav", clam_raw)
    document_warnings.extend(clam_warnings)
    document_errors.extend(clam_errors)
    infected = clam_raw.get("Infected files")
    detected = None
    if infected is not None and not clam_errors:
        try:
            detected = int(infected) > 0
        except (TypeError, ValueError):
            clam_warnings.append(_condition("clamav", "invalid_infected_files", str(infected)))
            document_warnings.append(clam_warnings[-1])

    yara_raw = scan.get("yara", {})
    yara_warnings, yara_errors = _classify_conditions("yara", yara_raw)
    document_warnings.extend(yara_warnings)
    document_errors.extend(yara_errors)

    hash_raw = scan.get("hash", {})
    entropy_raw = scan.get("entropy", {})
    entropy_warnings, entropy_errors = _classify_conditions("entropy", entropy_raw)
    document_warnings.extend(entropy_warnings)
    document_errors.extend(entropy_errors)

    insights = event.get("insights", scan.get("insights", []))
    if not isinstance(insights, list):
        insights = [insights]

    evidence = {
        "schema_version": "1.0.0",
        "source": "strelka",
        "status": _status(document_warnings, document_errors),
        "request_id": str(tree.get("root", event.get("request_id", event.get("id", "")))),
        "file": {
            "filename": str(file_data.get("name", "")),
            "size_bytes": file_data.get("size", 0),
            "depth": file_data.get("depth", 0),
            "flavors": deepcopy(file_data.get("flavors", {})),
            "scanners_run": [_canonical_scanner(str(name)) for name in file_data.get("scanners", [])],
        },
        "hashes": {
            "md5": hash_raw.get("md5"),
            "sha1": hash_raw.get("sha1"),
            "sha256": hash_raw.get("sha256"),
            "ssdeep": hash_raw.get("ssdeep"),
            "tlsh": hash_raw.get("tlsh"),
        },
        "clamav": {
            "status": _status(clam_warnings, clam_errors),
            "detected": detected,
            "engine_version": clam_raw.get("Engine version"),
            "warnings": clam_warnings,
            "errors": clam_errors,
        },
        "yara": {
            "status": _status(yara_warnings, yara_errors),
            "matches": deepcopy(yara_raw.get("matches", [])),
            "rules_loaded": yara_raw.get("rules_loaded", 0),
            "flags": deepcopy(yara_raw.get("flags", [])),
            "warnings": yara_warnings,
            "errors": yara_errors,
        },
        "entropy": {
            "status": _status(entropy_warnings, entropy_errors),
            "value": entropy_raw.get("entropy"),
            "severity": "informational",
            "warnings": entropy_warnings,
            "errors": entropy_errors,
        },
        "insights": deepcopy(insights),
        "warnings": document_warnings,
        "errors": document_errors,
    }
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, help="Raw Strelka JSON (defaults to stdin)")
    parser.add_argument("-o", "--output", type=Path, help="Output file (defaults to stdout)")
    args = parser.parse_args(argv)

    if args.input:
        raw = json.loads(args.input.read_text(encoding="utf-8"))
    else:
        raw = json.load(sys.stdin)
    rendered = json.dumps(normalize_strelka(raw), indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
