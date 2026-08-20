"""Thin FileGuard JSON wrapper around upstream YARA."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yara
except ImportError:
    yara = None


SCANNER_VERSION = "0.1.0"
RULE_SUFFIXES = {".yar", ".yara"}


class YaraUnavailableError(RuntimeError):
    """Raised when the upstream YARA binding is not installed."""


def discover_rules(rules_directory: str | Path) -> list[Path]:
    root = Path(rules_directory)
    if not root.is_dir():
        raise FileNotFoundError(f"Rules directory does not exist: {root}")
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in RULE_SUFFIXES
    )
    if not files:
        raise ValueError(f"No YARA rules found under: {root}")
    return files


def namespace_for(rule_path: Path, rules_root: Path) -> str:
    relative = rule_path.relative_to(rules_root).with_suffix("").as_posix()
    namespace = re.sub(r"[^A-Za-z0-9_]", "_", relative.replace("/", "_"))
    return namespace or "default"


def ruleset_version(rule_files: list[Path], rules_root: Path) -> str:
    digest = hashlib.sha256()
    for rule_file in rule_files:
        relative = rule_file.relative_to(rules_root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with rule_file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def compile_rules(rules_directory: str | Path):
    if yara is None:
        raise YaraUnavailableError(
            "yara-python is unavailable; install the pinned scanner requirements"
        )
    root = Path(rules_directory).resolve()
    files = discover_rules(root)
    filepaths = {namespace_for(path, root): str(path) for path in files}
    return yara.compile(filepaths=filepaths), files, root


def _json_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, bytes):
            normalized[key] = value.decode("utf-8", errors="replace")
        elif isinstance(value, (str, int, float, bool)) or value is None:
            normalized[key] = value
        else:
            normalized[key] = str(value)
    return normalized


def normalize_match(match: Any) -> dict[str, Any]:
    metadata = _json_metadata(dict(match.meta))
    return {
        "name": match.rule,
        "namespace": match.namespace,
        "metadata": metadata,
        "severity": metadata.get("severity"),
        "confidence": metadata.get("confidence"),
    }


def scan_file(
    file_path: str | Path,
    rules_directory: str | Path,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    sample = Path(file_path)
    if not sample.exists():
        raise FileNotFoundError(f"Sample does not exist: {sample}")
    if not sample.is_file():
        raise ValueError(f"Sample is not a regular file: {sample}")

    compiled, files, root = compile_rules(rules_directory)
    matches = compiled.match(filepath=str(sample), timeout=timeout_seconds)
    normalized = sorted(
        (normalize_match(match) for match in matches),
        key=lambda item: (item["namespace"], item["name"]),
    )
    return {
        "scanner": "yara",
        "scanner_version": SCANNER_VERSION,
        "status": "complete",
        "detected": bool(normalized),
        "matched_rules": normalized,
        "ruleset_version": ruleset_version(files, root),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan one untrusted file with YARA.")
    parser.add_argument("file", help="Path to the mounted sample")
    parser.add_argument(
        "--rules",
        default="/rules/yara",
        help="Root directory containing .yar and .yara files",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="YARA scan timeout in seconds",
    )
    args = parser.parse_args()

    try:
        output = scan_file(args.file, args.rules, args.timeout)
    except Exception as error:
        output = {
            "scanner": "yara",
            "scanner_version": SCANNER_VERSION,
            "status": "error",
            "detected": None,
            "matched_rules": [],
            "ruleset_version": "unknown",
            "error": {"code": type(error).__name__, "message": str(error)},
        }
        print(json.dumps(output, sort_keys=True))
        return 2

    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
