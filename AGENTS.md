# AGENTS.md

## Purpose

FileGuard is a proof-of-concept secure file-intake and malware-analysis platform, designed to grow into an AWS-hosted system. It accepts files, runs static analysis, applies a policy-based disposition decision, and (planned) routes eligible quarantined files to isolated dynamic analysis.

## Current architecture

```
Strelka UI/API wrapper
  → FileGuard extractor       (extractors/strelka_ui.py)
  → raw Strelka event
  → FileGuard normalizer      (normalizers/strelka.py)
  → normalized static evidence (schemas/static-evidence.schema.json)
  → OPA policy decision       (policies/fileguard/disposition.rego)
```

- **Strelka** is the current static-analysis framework.
- **OPA** is the disposition policy engine. Conclusions: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `INCOMPLETE`.
- **CAPE** is the planned internal dynamic-analysis layer for eligible quarantined files — part of the architecture, not deferred.
- **Thorium has been retired** from the architecture. Do not reintroduce it.
- **VirusTotal and Cuckoo/CuckooBox** are optional, policy-gated integrations — not implemented.
- AWS hosting, CAPE integration, S3 disposition execution, and scaling are not implemented yet.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full component detail.

## Current implementation phase

**Phase 4 complete: local disposition execution implemented and validated, on top of the completed four-outcome OPA policy.**

- `CLEAN`, `INCOMPLETE`, `SUSPICIOUS`, `MALICIOUS` — all implemented, unit-tested, and validated end-to-end against real Strelka output. Precedence: `MALICIOUS` > `INCOMPLETE` > `SUSPICIOUS` > `CLEAN` > default fail-closed `INCOMPLETE`; `clamav.detected == true` is the sole MALICIOUS trigger.
- Local disposition execution (`disposition.py`) acts on OPA decisions: `CLEAN → clean/`, `INCOMPLETE`/`SUSPICIOUS`/`MALICIOUS → quarantine/`, via a fail-closed copy → verify (SHA-256) → atomic no-overwrite publish → source-delete sequence. Validated with real OPA in WSL (`41 passed, 0 skipped`).
- Next phase: **CAPE integration**. Not started — do not begin without explicit direction.

See [docs/CURRENT-STATE.md](docs/CURRENT-STATE.md) for the full checkpoint.

## Local pipeline runner

`python -m pipeline <strelka-wrapper.json>` runs the full chain (extractor → normalizer → schema validation → OPA) and prints `{static_evidence, opa_decision}`. Fails closed on any stage error, including a missing/broken `opa` executable — never exits 0 without a valid decision. See `pipeline.py`.

## Local disposition executor

`python -m disposition <source> <decision.json> --clean-dir <dir> --quarantine-dir <dir>` (or `execute_disposition(source_path, decision, clean_dir, quarantine_dir)`) moves a file per an OPA decision: SHA-256 the source, copy to a temp file in the destination directory, SHA-256 the copy, compare, publish via `os.link` (atomically refuses to overwrite an existing destination — not an `exists()` pre-check), then delete the source. Malformed decisions or unrecognized/mismatched `(conclusion, destination)` pairs fail before any file is touched. If source deletion fails after a verified publish, that's still a `DispositionError` (stage `source_delete`, not success) — the destination copy is kept, not rolled back. Runtime directories live under the gitignored `/local-data/`, never committed. See `disposition.py`.

## ClamAV evidence

Normalized `clamav.signatures` retains detected signature names (e.g. `"Eicar-Test-Signature"`) as a deduplicated, first-seen-order list — `[]` on clean scans. Signature names are evidence for analysts and future intelligence use only; `clamav.detected == true` remains the sole MALICIOUS policy trigger.

## Key security principles

- **Fail closed.** Incomplete analysis, scanner failure, or any warning that prevents a clean determination must never resolve to `CLEAN`.
- Never commit malware samples, secrets, credentials, private keys, controlled information, or sensitive analysis output.
- External integrations (VirusTotal, Cuckoo) must remain optional and policy-gated, not hard dependencies.
- Temporary root-level `*-wrapper.json` validation captures are gitignored — never commit them; sanitized regression fixtures belong under `tests/fixtures/...`.

## Strelka/YARA invariant

FileGuard currently uses source `.yar`/`.yara` rules, not a compiled ruleset. `config/strelka/backend.yaml` is the FileGuard-owned, Git-tracked source of truth for the Strelka backend config — `ScanYara.options.compiled.enabled` must remain `False` there unless a valid `rules.compiled` file is deliberately built and deployed; enabling it without a real compiled file reintroduces `compiled_load_error` and makes FileGuard classify scans as `INCOMPLETE`. The original Strelka quickstart rule (`rule test { condition: true }`, which matches every file and blocks `CLEAN`) must not be restored to `config/strelka/yara/rules.yara`.

`config/strelka/` is only authoritative when the running Strelka backend is started with `docker-compose.strelka.override.yml` layered on top of `strelka/build/docker-compose-no-build.yaml` (see that file's header comment for the exact command). Starting Strelka from the upstream compose files alone still uses the vendor configuration under the gitignored `strelka/` clone — do not edit files inside `strelka/` to change FileGuard behavior; edit `config/strelka/` instead. Use `docker-compose-no-build.yaml` (prebuilt image), not `docker-compose.yaml` (build-from-source, which triggers the upstream Strelka test suite — unrelated to FileGuard and not this project's concern).

## Important directories

- `extractors/` — pulls raw Strelka events out of the Strelka UI/API wrapper.
- `normalizers/` — converts raw Strelka events into normalized FileGuard static evidence.
- `policies/fileguard/` — OPA disposition policy (Rego).
- `schemas/` — evidence and decision schemas. `static-evidence.schema.json` is the current schema in active use.
- `tests/` — unit tests plus real and reconstructed fixtures for the extractor, normalizer, and policy.
- `docs/` — architecture and project documentation (this file links to it).
- `config/strelka/` — FileGuard-owned, Git-tracked Strelka backend config (`backend.yaml`, `yara/rules.yara`), consumed via `docker-compose.strelka.override.yml`. See Strelka/YARA invariant above.
- `strelka/` — local Strelka clone/dev environment (gitignored, not tracked). Upstream software dependency only — not the configuration source of truth.
- `scanners/` — **legacy/reference only.** Pre-Strelka custom scanner PoCs (capa, clamav, classifier, office-analysis, pdf-analysis, scoring-engine), retained for future Strelka gap analysis. Do not treat as part of the current pipeline.
- `terraform/`, `kubernetes/` — placeholders for future AWS/K8s infrastructure. Mostly empty (`.gitkeep`).

## Rules Codex should follow

- Do not reintroduce Thorium as the current architecture.
- Do not begin CAPE integration (or IoCs, notifications, AWS) without explicit direction — current phase boundary is the completed local disposition executor.
- Do not treat `scanners/` as current implementation; it is legacy/reference.
- Do not treat `kubernetes/thorium/`, `schemas/verdict.schema.json`, `schemas/scanner-result.schema.json`, or `schemas/classifier-result.schema.json` as part of the current architecture — they are known legacy artifacts from the pre-Strelka/pre-OPA direction. See [docs/DECISIONS.md](docs/DECISIONS.md).
- Preserve fail-closed behavior in any policy or normalizer change.
- Work one phase at a time; avoid overengineering the PoC (no AWS, CAPE, or external-integration code until those phases start).

## Test commands

```bash
# Install test dependencies (pytest, jsonschema)
pip install -r requirements-dev.txt

# Extractor and normalizer tests
python -m pytest tests/test_strelka_extractor.py tests/test_strelka_normalizer.py -q

# OPA policy and pipeline tests (require the `opa` CLI on PATH; auto-skip if absent)
python -m pytest tests/test_fileguard_policy.py tests/test_pipeline.py -q

# Full suite — passes with 0 skips when `opa` is on PATH (confirmed in WSL, OPA 1.19.1)
python -m pytest tests/ -q
```

## Deeper docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — component responsibilities, implemented vs. planned.
- [docs/CURRENT-STATE.md](docs/CURRENT-STATE.md) — project checkpoint, completed work, next step.
- [docs/DECISIONS.md](docs/DECISIONS.md) — architectural decisions and rationale.
