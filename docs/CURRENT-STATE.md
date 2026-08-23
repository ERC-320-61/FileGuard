# FileGuard — Current State

Checkpoint as of 2026-08-22. Update this file as phases complete so a new session can recover context quickly.

## Completed work

- Strelka runs locally (`strelka/`, gitignored local dev environment).
- Strelka UI/API wrapper extraction implemented and tested (`extractors/strelka_ui.py`).
- Raw Strelka event normalization implemented and tested (`normalizers/strelka.py`).
- `schemas/static-evidence.schema.json` defines the normalized static-evidence contract.
- Real (`image.jpg.real.json`) and reconstructed (`image.jpg.json`) Strelka fixtures exist under `tests/fixtures/strelka/`.
- Extractor and normalizer tests pass (`tests/test_strelka_extractor.py`, `tests/test_strelka_normalizer.py`).
- OPA installed and available locally (confirmed: OPA 1.19.1 in the developer's WSL environment at `/usr/local/bin/opa`; not on PATH in every execution environment — see Known limitations).
- Initial OPA policy implemented and tested (`policies/fileguard/disposition.rego`):
  - Fail-closed `INCOMPLETE` → quarantine default and explicit incomplete-status rule.
  - `CLEAN` rule — **completed**: full pass (complete status, clamav clean, yara no matches, zero warnings/errors) → `CLEAN`, destination clean, no review required.
- Policy tests (`tests/test_fileguard_policy.py`) cover: incomplete evidence → quarantine, unmatched evidence fails closed, qualifying evidence → `CLEAN`, a warning prevents `CLEAN`, a scanner-incomplete state prevents `CLEAN`.
- Local Strelka YARA configuration validated end-to-end (2026-08-23):
  - **Problem:** `strelka/configs/python/backend/backend.yaml` had `ScanYara.options.compiled.enabled: True` pointing at `/etc/strelka/yara/rules.compiled`, which did not exist. Every `ScanYara` run emitted `compiled_load_error_could not open file "/etc/strelka/yara/rules.compiled"`, and Strelka fell back to compiling the source rules. FileGuard's normalizer correctly treated that flag as a warning, so `yara.status` and the overall document `status` came out `incomplete` — no submission could ever reach `CLEAN`.
  - **Fix:** set `compiled.enabled: False` in `backend.yaml` so Strelka loads the source `.yar`/`.yara` rules directly, no compiled ruleset involved.
  - **Second problem:** the source rule file (`strelka/configs/python/backend/yara/rules.yara`) still held the Strelka quickstart rule (`rule test { condition: true }`), which matches every file — this alone would block `CLEAN` for all submissions regardless of the compiled-loading fix.
  - **Fix:** replaced it with a deterministic, harmless marker rule, `FileGuard_Harmless_Test_Marker`, matching only the literal string `FILEGUARD_YARA_TEST`.
  - **Validation results** (Strelka backend restarted to reload rules): `fileguard-clean-test.txt` → `rules_loaded = 1`, `matches = []`, `yara_hits = []`, no `compiled_load_error`, ClamAV `Infected files = 0`. `fileguard-yara-test.txt` (containing `FILEGUARD_YARA_TEST`) → `rules_loaded = 1`, `matches = ["FileGuard_Harmless_Test_Marker"]`, `yara_hits = ["FileGuard_Harmless_Test_Marker"]`, no `compiled_load_error`, ClamAV `Infected files = 0`. Confirms `compiled.enabled` stays `False`, source rules load cleanly, ordinary files no longer get an automatic YARA hit, and the marker rule fires deterministically only on its target string.
- Strelka config moved from manual edits inside the gitignored `strelka/` clone to a Git-tracked FileGuard-owned source of truth (2026-08-23):
  - `config/strelka/backend.yaml` and `config/strelka/yara/rules.yara` now hold the validated known-good configuration (`compiled.enabled: False`, `FileGuard_Harmless_Test_Marker` rule, no always-true `test` rule).
  - `docker-compose.strelka.override.yml` (FileGuard repo root) layers these two files onto the `backend` service's `/etc/strelka/backend.yaml` and `/etc/strelka/yara/rules.yara` via additional bind mounts, on top of the upstream directory mount (`strelka/build/docker-compose-no-build.yaml` + `strelka/build/docker-compose.yaml` both mount `strelka/configs/python/backend/` → `/etc/strelka/`). Everything else under `/etc/strelka/` (`logging.yaml`, `passwords.dat`, `suricata/`, `taste/`, `tlsh/`) still comes from the vendor clone.
  - `config/strelka/` is **only authoritative when the override is used**. Starting Strelka from the base compose file alone still uses the vendor configuration under `strelka/`. The upstream `strelka/` clone remains gitignored — it is the software dependency, not the config source of truth.
  - Use the prebuilt stack (`strelka/build/docker-compose-no-build.yaml`) for this work, not `strelka/build/docker-compose.yaml` — the build-from-source file triggers the upstream Strelka test suite, which failed locally on a missing upstream fixture (`strelka/strelka/tests/fixtures/test.xls`) unrelated to FileGuard configuration; that build path was not troubleshot as it's out of scope.
  - Runtime validation (2026-08-23, prebuilt image `target/strelka-backend:latest`, recreated via `docker compose -f strelka/build/docker-compose-no-build.yaml -f docker-compose.strelka.override.yml up -d --force-recreate backend`): in-container `/etc/strelka/backend.yaml` shows `compiled.enabled: False`; in-container `/etc/strelka/yara/rules.yara` shows only `FileGuard_Harmless_Test_Marker` (no `rule test`); `diff` between the running container's files and the tracked `config/strelka/` files was empty for both (identical).
  - Strelka image pinning (`target/strelka-backend:latest`) is a separate, deliberately deferred reproducibility gap — not addressed by this config-tracking work.

## Current phase

**Phase 3: OPA policy decisions.**

## Current task

CLEAN is implemented and tested. The active task is validating that CLEAN behaves correctly across more evidence shapes before extending the ruleset.

## Tests currently passing

- `tests/test_strelka_extractor.py`, `tests/test_strelka_normalizer.py` — pass (require `jsonschema`; no root-level requirements manifest exists yet, install manually).
- `tests/test_fileguard_policy.py` — passes when `opa` is on PATH (verified by the developer in WSL, OPA 1.19.1). Tests self-skip via `unittest.skipUnless` when `opa` is not found, so a clean unittest run in an environment without OPA on PATH will silently skip these 5 tests rather than fail. Not every execution environment (e.g. this session's default shell) has `opa` on PATH — treat that as an environment difference, not evidence OPA is missing from the project.

## Known limitations

- No root-level Python dependency manifest (`requirements.txt` / `pyproject.toml`) for `extractors/`, `normalizers/`, or `tests/` — `jsonschema` must be installed manually.
- OPA policy tests are environment-dependent (require `opa` on PATH) and skip silently rather than fail when it's absent.
- Only `INCOMPLETE` and `CLEAN` disposition conclusions exist; `SUSPICIOUS` and `MALICIOUS` are undefined, so any evidence that doesn't match the CLEAN or incomplete rules falls through to the fail-closed `INCOMPLETE` default.
- No disposition worker exists to act on OPA decisions.
- CAPE, AWS, VirusTotal, and Cuckoo integrations are undesigned beyond the architectural placement described in `docs/ARCHITECTURE.md`.
- `scanners/`, `kubernetes/thorium/`, and the `verdict`/`scanner-result`/`classifier-result` schemas are legacy artifacts from the pre-Strelka/pre-OPA direction (see `docs/DECISIONS.md`) and should not be extended as if they were current.

## What must NOT be implemented yet

- `SUSPICIOUS` or `MALICIOUS` OPA disposition rules.
- CAPE integration.
- S3 disposition execution or any AWS service integration.
- Scaling work of any kind.
- Do not reintroduce Thorium as the current architecture.

## Immediate next step

Validate the completed CLEAN policy and decide which disposition conclusion to implement next.
