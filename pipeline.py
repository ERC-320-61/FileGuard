"""Run the FileGuard static disposition pipeline end to end.

Strelka UI/API wrapper JSON
  -> extract_strelka_event()
  -> normalize_strelka()
  -> static-evidence schema validation
  -> OPA disposition decision
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from extractors.strelka_ui import extract_strelka_event
from normalizers.strelka import normalize_strelka


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "schemas" / "static-evidence.schema.json"
POLICY_PATH = ROOT / "policies" / "fileguard" / "disposition.rego"
OPA_QUERY = "data.fileguard.disposition.decision"


class PipelineError(Exception):
    """Raised when any pipeline stage fails. Always fail closed."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"{stage} failed: {message}")


def _load_wrapper(wrapper: Any) -> dict[str, Any]:
    if not isinstance(wrapper, dict):
        raise PipelineError("wrapper_load", "wrapper JSON must be an object")
    return wrapper


def _extract(wrapper: dict[str, Any]) -> dict[str, Any]:
    try:
        return extract_strelka_event(wrapper)
    except ValueError as exc:
        raise PipelineError("extraction", str(exc)) from exc


def _normalize(event: dict[str, Any]) -> dict[str, Any]:
    try:
        return normalize_strelka(event)
    except ValueError as exc:
        raise PipelineError("normalization", str(exc)) from exc


def _validate_schema(evidence: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(evidence), key=lambda e: list(e.path))
    if errors:
        messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
        raise PipelineError("schema_validation", messages)


def _run_opa(evidence: dict[str, Any]) -> dict[str, Any]:
    opa = shutil.which("opa")
    if not opa:
        raise PipelineError(
            "opa_unavailable",
            "the 'opa' executable was not found on PATH",
        )

    with tempfile.TemporaryDirectory() as temporary_directory:
        input_path = Path(temporary_directory) / "evidence.json"
        input_path.write_text(json.dumps(evidence), encoding="utf-8")
        process = subprocess.run(
            [
                opa,
                "eval",
                "--format=json",
                "--data",
                str(POLICY_PATH),
                "--input",
                str(input_path),
                OPA_QUERY,
            ],
            capture_output=True,
            check=False,
            text=True,
        )

    if process.returncode != 0:
        raise PipelineError(
            "opa_execution",
            process.stderr.strip() or process.stdout.strip() or "unknown OPA error",
        )

    try:
        result = json.loads(process.stdout)
        return result["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise PipelineError("opa_response", f"malformed OPA response: {exc}") from exc


def run_pipeline(wrapper: Any) -> dict[str, Any]:
    """Run the full static disposition pipeline and return static_evidence + opa_decision.

    Fails closed: raises PipelineError on any stage failure, including a
    missing or malfunctioning OPA executable. Never returns without a valid
    OPA decision.
    """
    wrapper = _load_wrapper(wrapper)
    event = _extract(wrapper)
    evidence = _normalize(event)
    _validate_schema(evidence)
    decision = _run_opa(evidence)

    return {
        "static_evidence": evidence,
        "opa_decision": decision,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wrapper", type=Path, help="Strelka UI/API wrapper JSON file")
    args = parser.parse_args(argv)

    try:
        wrapper = json.loads(args.wrapper.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"wrapper_load failed: {exc}", file=sys.stderr)
        return 1

    try:
        result = run_pipeline(wrapper)
    except PipelineError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # fail closed on any unexpected error
        print(f"unexpected pipeline failure: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
