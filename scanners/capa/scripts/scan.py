"""Thin FileGuard JSON wrapper around upstream capa."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCANNER_VERSION = "0.1.0"
RULESET_VERSION = "v9.4.0"
RULES_DIRECTORY = "/opt/capa-rules"
SIGNATURES_DIRECTORY = "/opt/capa-sigs"
DEFAULT_TIMEOUT_SECONDS = 300
UNSUPPORTED_MARKERS = (
    "unsupported file",
    "unsupported format",
    "does not appear to be a supported",
    "not a pe file",
    "could not detect",
    "invalid file format",
)


class UnsupportedFileError(RuntimeError):
    """Raised when capa cannot analyze the submitted format."""


class CapaScannerError(RuntimeError):
    """Raised when capa fails for a reason other than unsupported input."""


def _run(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def capa_engine_version() -> str:
    result = _run(["capa", "--version"], 15)
    if result.returncode != 0:
        return "unknown"
    output = (result.stdout or result.stderr).strip()
    match = re.search(r"\d+(?:\.\d+)+", output)
    return match.group(0) if match else output or "unknown"


def _stable_value(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if value not in (None, "", [], {}):
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
    return "unknown"


def extract_ruleset_version(document: dict[str, Any]) -> str:
    meta = document.get("meta") or {}
    analysis = meta.get("analysis") or {}
    for value in (
        meta.get("ruleset_version"),
        analysis.get("ruleset_version"),
    ):
        normalized = _stable_value(value)
        if normalized != "unknown":
            return normalized
    return RULESET_VERSION


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def normalize_attack_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    raw = str(value)
    match = re.search(r"\[(T\d+(?:\.\d+)?)\]\s*$", raw)
    technique_id = match.group(1) if match else None
    name = raw[: match.start()].strip() if match else raw
    return {"id": technique_id, "name": name, "raw": raw}


def normalize_capabilities(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_rules = document.get("rules") or {}
    entries = raw_rules.items() if isinstance(raw_rules, dict) else (
        (str(index), item) for index, item in enumerate(raw_rules)
    )
    capabilities: list[dict[str, Any]] = []
    aggregate_attack: dict[str, dict[str, Any]] = {}

    for fallback_name, rule in entries:
        rule = rule if isinstance(rule, dict) else {}
        metadata = dict(rule.get("meta") or {})
        if metadata.get("lib") or metadata.get("is_subscope_rule"):
            continue
        name = str(metadata.get("name") or fallback_name)
        namespace = metadata.get("namespace")
        categories = _as_list(metadata.get("categories") or metadata.get("category"))
        raw_attack = (
            metadata.get("att&ck")
            or metadata.get("attack")
            or metadata.get("ATT&CK")
        )
        attack = [normalize_attack_mapping(item) for item in _as_list(raw_attack)]
        for mapping in attack:
            key = json.dumps(mapping, sort_keys=True)
            aggregate_attack[key] = mapping
        capabilities.append(
            {
                "name": name,
                "namespace": namespace,
                "categories": categories,
                "attack": attack,
                "metadata": metadata,
            }
        )

    capabilities.sort(key=lambda item: (str(item["namespace"]), item["name"]))
    attack_mappings = sorted(
        aggregate_attack.values(),
        key=lambda item: (str(item.get("id")), str(item.get("name"))),
    )
    return capabilities, attack_mappings


def parse_capa_document(document: dict[str, Any], engine_version: str) -> dict[str, Any]:
    capabilities, attack_mappings = normalize_capabilities(document)
    json_version = ((document.get("meta") or {}).get("version"))
    return {
        "scanner": "capa",
        "scanner_version": SCANNER_VERSION,
        "status": "complete",
        "analyzed": True,
        "capabilities": capabilities,
        "attack_mappings": attack_mappings,
        "engine_version": str(json_version or engine_version),
        "ruleset_version": extract_ruleset_version(document),
    }


def scan_file(
    file_path: str | Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    sample = Path(file_path)
    if not sample.exists():
        raise FileNotFoundError(f"Sample does not exist: {sample}")
    if not sample.is_file():
        raise ValueError(f"Sample is not a regular file: {sample}")

    engine_version = capa_engine_version()
    result = _run(
        [
            "capa",
            "-j",
            "-r",
            RULES_DIRECTORY,
            "-s",
            SIGNATURES_DIRECTORY,
            str(sample),
        ],
        timeout_seconds,
    )
    if result.returncode != 0:
        detail = "\n".join(
            stream.strip() for stream in (result.stdout, result.stderr) if stream.strip()
        ) or "unknown capa error"
        if any(marker in detail.lower() for marker in UNSUPPORTED_MARKERS):
            raise UnsupportedFileError(detail)
        raise CapaScannerError(
            f"capa failed with exit code {result.returncode}: {detail}"
        )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CapaScannerError(f"capa returned invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise CapaScannerError("capa JSON output is not an object")
    return parse_capa_document(document, engine_version)


def _error_result(status: str, error: Exception) -> dict[str, Any]:
    return {
        "scanner": "capa",
        "scanner_version": SCANNER_VERSION,
        "status": status,
        "analyzed": False,
        "capabilities": [],
        "attack_mappings": [],
        "engine_version": "unknown",
        "ruleset_version": "unknown",
        "error": {"code": type(error).__name__, "message": str(error)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze one file with capa.")
    parser.add_argument("file", help="Path to the mounted sample")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()
    try:
        output = scan_file(args.file, args.timeout)
    except UnsupportedFileError as error:
        output = _error_result("unsupported", error)
        print(json.dumps(output, sort_keys=True))
        return 3
    except Exception as error:
        output = _error_result("error", error)
        print(json.dumps(output, sort_keys=True))
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
