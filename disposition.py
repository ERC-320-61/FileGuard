"""Execute a FileGuard disposition decision against a local file.

source
  -> SHA-256
  -> temporary copy in target directory (clean_dir or quarantine_dir)
  -> destination SHA-256
  -> compare
  -> no-overwrite publish (hard link + unlink temp)
  -> source deletion

This is the local equivalent of the future AWS S3 copy -> verify -> delete
disposition workflow. Fails closed at every stage: a malformed or unknown
decision, or any I/O failure, never results in the source being deleted or a
destination file being silently overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


VALID_DISPOSITIONS = {
    ("CLEAN", "clean"),
    ("INCOMPLETE", "quarantine"),
    ("SUSPICIOUS", "quarantine"),
    ("MALICIOUS", "quarantine"),
}

_CHUNK_SIZE = 1024 * 1024


class DispositionError(Exception):
    """Raised when disposition fails. Always fail closed.

    destination_path is set only when a verified destination copy already
    exists at the time of failure (currently: source deletion failed after a
    successful, verified publish) so callers know not to re-run the copy.
    """

    def __init__(self, stage: str, message: str, destination_path: Path | None = None) -> None:
        self.stage = stage
        self.destination_path = destination_path
        super().__init__(f"{stage} failed: {message}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_decision(decision: Any) -> str:
    if not isinstance(decision, dict):
        raise DispositionError("decision_malformed", "decision must be an object")

    conclusion = decision.get("conclusion")
    destination = decision.get("destination")
    if not isinstance(conclusion, str) or not isinstance(destination, str):
        raise DispositionError(
            "decision_malformed",
            "decision must include string 'conclusion' and 'destination' fields",
        )
    if destination not in {"clean", "quarantine"}:
        raise DispositionError("decision_unknown_destination", f"unrecognized destination: {destination!r}")
    if (conclusion, destination) not in VALID_DISPOSITIONS:
        raise DispositionError(
            "decision_conclusion_destination_mismatch",
            f"conclusion {conclusion!r} does not match destination {destination!r}",
        )
    return destination


def _publish_without_overwrite(temp_path: Path, final_path: Path) -> None:
    """Publish temp_path as final_path without ever overwriting an existing
    file. Uses a hard link (which fails atomically with FileExistsError if
    final_path already exists) followed by unlinking the temp name, rather
    than os.replace()/os.rename(), which either overwrite unconditionally
    (os.replace, and os.rename on POSIX) or behave inconsistently across
    platforms (bare os.rename). The existence check and the publish happen
    as a single kernel operation, so there is no check-then-act race.
    """
    os.link(temp_path, final_path)
    temp_path.unlink()


def execute_disposition(
    source_path: Path,
    decision: dict,
    clean_dir: Path,
    quarantine_dir: Path,
) -> dict:
    """Copy source_path to clean_dir or quarantine_dir per decision, verify
    the copy by SHA-256, then delete source_path.

    Raises DispositionError on any failure. Never overwrites an existing
    destination file. Never deletes source_path unless a verified copy has
    already been safely published at the final destination path -- if that
    final deletion itself fails, DispositionError is still raised (stage
    "source_delete") with destination_path set, so the caller knows a
    verified copy exists even though the operation did not fully complete.
    """
    source_path = Path(source_path)
    clean_dir = Path(clean_dir)
    quarantine_dir = Path(quarantine_dir)

    if not source_path.exists():
        raise DispositionError("source_missing", f"source does not exist: {source_path}")
    if not source_path.is_file():
        raise DispositionError("source_invalid", f"source is not a regular file: {source_path}")

    destination = _validate_decision(decision)
    target_dir = clean_dir if destination == "clean" else quarantine_dir

    if not target_dir.is_dir():
        raise DispositionError("destination_dir_missing", f"destination directory does not exist: {target_dir}")

    final_path = target_dir / source_path.name
    if final_path.exists():
        raise DispositionError("destination_exists", f"destination already exists: {final_path}")

    source_sha256 = _sha256(source_path)

    temp_path = target_dir / f".tmp-{uuid.uuid4().hex}-{source_path.name}"
    try:
        with source_path.open("rb") as src, temp_path.open("wb") as dst:
            for chunk in iter(lambda: src.read(_CHUNK_SIZE), b""):
                dst.write(chunk)
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        raise DispositionError("copy_failed", str(exc)) from exc

    destination_sha256 = _sha256(temp_path)
    if destination_sha256 != source_sha256:
        temp_path.unlink(missing_ok=True)
        raise DispositionError(
            "verification_failed",
            f"sha256 mismatch: source={source_sha256} destination={destination_sha256}",
        )

    try:
        _publish_without_overwrite(temp_path, final_path)
    except FileExistsError as exc:
        temp_path.unlink(missing_ok=True)
        raise DispositionError("destination_exists", f"destination already exists: {final_path}") from exc
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        raise DispositionError("publish_failed", str(exc)) from exc

    try:
        source_path.unlink()
    except OSError as exc:
        raise DispositionError(
            "source_delete",
            f"a verified destination copy already exists at {final_path}, "
            f"but deleting the source failed and it was left in place: {exc}",
            destination_path=final_path,
        ) from exc

    return {
        "destination": destination,
        "destination_path": final_path,
        "sha256": source_sha256,
        "source_deleted": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Source file to disposition")
    parser.add_argument("decision", type=Path, help="OPA decision JSON file")
    parser.add_argument("--clean-dir", type=Path, required=True)
    parser.add_argument("--quarantine-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        decision = json.loads(args.decision.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"decision_load failed: {exc}", file=sys.stderr)
        return 1

    try:
        result = execute_disposition(args.source, decision, args.clean_dir, args.quarantine_dir)
    except DispositionError as exc:
        print(str(exc), file=sys.stderr)
        if exc.destination_path is not None:
            print(f"note: a verified destination copy already exists at {exc.destination_path}", file=sys.stderr)
        return 1
    except Exception as exc:  # fail closed on any unexpected error
        print(f"unexpected disposition failure: {exc}", file=sys.stderr)
        return 1

    rendered = {**result, "destination_path": str(result["destination_path"])}
    print(json.dumps(rendered, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
