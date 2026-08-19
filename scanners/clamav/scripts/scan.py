"""Thin FileGuard JSON wrapper around the upstream ClamAV CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCANNER_VERSION = "0.1.0"


def parse_clamav_version(output: str) -> tuple[str, str]:
    """Parse ClamAV version output without assuming definitions exist."""
    value = output.strip()
    if value.lower().startswith("clamav "):
        value = value[7:]
    parts = value.split("/")
    engine_version = parts[0].strip() if parts and parts[0].strip() else "unknown"
    definition_version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "unknown"
    return engine_version, definition_version


def parse_detection(output: str) -> str | None:
    """Extract the signature from a ClamAV FOUND line."""
    for line in output.splitlines():
        if line.rstrip().endswith(" FOUND"):
            finding = line.rsplit(": ", 1)[-1]
            return finding[: -len(" FOUND")].strip() or None
    return None


def _version() -> tuple[str, str]:
    result = subprocess.run(
        ["clamscan", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return "unknown", "unknown"
    return parse_clamav_version(result.stdout or result.stderr)


def scan_file(file_path: str | Path) -> dict[str, Any]:
    """Scan one regular file without modifying or executing it."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Sample does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Sample is not a regular file: {path}")

    engine_version, definition_version = _version()
    result = subprocess.run(
        ["clamscan", "--no-summary", "--stdout", "--infected", "--", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode == 0:
        detected = False
        signature = None
    elif result.returncode == 1:
        detected = True
        signature = parse_detection(result.stdout)
        if signature is None:
            raise RuntimeError("ClamAV reported a detection without a parseable signature")
    else:
        detail = "\n".join(
            stream.strip() for stream in (result.stdout, result.stderr) if stream.strip()
        ) or "unknown ClamAV error"
        raise RuntimeError(f"ClamAV scan failed with exit code {result.returncode}: {detail}")

    return {
        "scanner": "clamav",
        "scanner_version": SCANNER_VERSION,
        "status": "complete",
        "detected": detected,
        "signature": signature,
        "engine_version": engine_version,
        "definition_version": definition_version,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan one untrusted file with ClamAV.")
    parser.add_argument("file", help="Path to the mounted sample")
    args = parser.parse_args()
    try:
        output = scan_file(args.file)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        output = {
            "scanner": "clamav",
            "scanner_version": SCANNER_VERSION,
            "status": "error",
            "detected": None,
            "signature": None,
            "engine_version": "unknown",
            "definition_version": "unknown",
            "error": {"code": type(error).__name__, "message": str(error)},
        }
        print(json.dumps(output, sort_keys=True))
        return 2

    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
