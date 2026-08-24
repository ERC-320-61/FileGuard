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
- Four-outcome OPA disposition policy completed and fully validated, real-world, end-to-end (2026-08-23):
  - `policies/fileguard/disposition.rego` restructured into a single deterministic `decision ... if { } else := ... if { }` chain (replacing three independent complete-rule definitions) implementing precedence `MALICIOUS > INCOMPLETE > SUSPICIOUS > CLEAN > default fail-closed INCOMPLETE`. A confirmed ClamAV detection (`clamav.status == "complete" AND clamav.detected == true`) is `MALICIOUS` even when other analysis in the same evidence document is incomplete — the destination is `quarantine` either way, but `MALICIOUS` preserves the stronger, more informative analyst-facing conclusion. No rule-name special-casing was added anywhere in policy code.
  - Synthetic fixtures (`tests/fixtures/fileguard/static-evidence.suspicious.json`, `.malicious.json`) plus 5 new tests in `tests/test_fileguard_policy.py` cover SUSPICIOUS, MALICIOUS, and every precedence/edge case (ClamAV-outranks-YARA, ClamAV-outranks-incomplete-status, incomplete-status-with-YARA-match-stays-INCOMPLETE).
  - **Real end-to-end pipeline validation completed for all four conclusions**, each via `python -m pipeline <wrapper.json>` against genuine Strelka output (not synthetic evidence): CLEAN (a real clean text file), INCOMPLETE (the tracked `image.jpg.real.json` wrapper), SUSPICIOUS (a fresh file containing `FILEGUARD_YARA_TEST`, matching the harmless `FileGuard_Harmless_Test_Marker` YARA rule — proves the pipeline escalates on a real match, not malware detection), and MALICIOUS (a safe, standard EICAR test artifact, detected by ClamAV — proves MALICIOUS is ClamAV-driven, since YARA correctly found no match on that content). All four exited `0` with the exact expected decision object. No application, policy, or config defect was exposed by any of these real-path runs.
  - ClamAV signature-name preservation implemented: `normalizers/strelka.py` now extracts detection names from raw `scan.clamav` values ending in `" FOUND"` (distinguishing them from fixed metadata keys like `Engine version`/`Infected files`/`elapsed` by value shape, not key allowlisting), deduplicating while preserving first-seen order, into a new `clamav.signatures` array (`schemas/static-evidence.schema.json` updated to match, `[]` on clean scans). The real EICAR run normalized to `signatures: ["Eicar-Test-Signature"]`. `clamav.detected` remains the only field OPA reads for MALICIOUS — signatures are evidence only, not a policy input. Per-child/temporary-path attribution is explicitly deferred; a future structured detection record can add that if needed.
  - Full test suite confirmed passing with real OPA in WSL: `22 passed, 0 skipped` after policy work, `15 passed, 12 skipped` (12 = OPA-gated tests, environment-dependent) most recently confirmed in this session's shell without `opa` on PATH — the WSL run with real OPA is the authoritative one.
  - `requirements-dev.txt` (repo root, added during the CI task) now declares `pytest` and `jsonschema` — the earlier "no root requirements manifest" limitation is resolved.
  - Temporary root-level `*-wrapper.json` validation captures are gitignored (`/*-wrapper.json`, root-anchored) and must not be committed; sanitized regression fixtures belong under `tests/fixtures/...` instead.
- Local disposition execution implemented and validated, real-world, with real OPA (2026-08-23):
  - New root module `disposition.py` (`execute_disposition(source_path, decision, clean_dir, quarantine_dir)` + `python -m disposition <source> <decision.json> --clean-dir <dir> --quarantine-dir <dir>` CLI) — the local equivalent of the future AWS S3 copy → verify → delete disposition workflow, operating on ordinary local directories.
  - Operational mapping (validated for all four): `CLEAN → clean/`; `INCOMPLETE`, `SUSPICIOUS`, `MALICIOUS → quarantine/`.
  - Safe sequence: source SHA-256 → copy to a uniquely-named temp file in the destination directory → destination SHA-256 → compare → publish (`os.link(temp_path, final_path)` then unlink the temp name) → delete source. `os.link` was deliberately chosen over `os.replace()`/`os.rename()`: it fails atomically with `FileExistsError` if the final path already exists, as a single kernel operation — there is no separate `exists()` check-then-act race window. A dedicated test (`test_publish_without_overwrite_refuses_existing_final_path`) exercises this primitive directly, bypassing the caller's own upfront check, to prove the guarantee doesn't depend on it.
  - Destination collisions fail closed: `DispositionError` (stage `destination_exists`), nothing overwritten, source untouched.
  - Decision validation happens before any file I/O: malformed decisions (not an object, missing/non-string `conclusion`/`destination`) and unrecognized or mismatched `(conclusion, destination)` pairs (e.g. `{"conclusion": "MALICIOUS", "destination": "clean"}`) both fail closed via an explicit allowlist of the four legitimate pairs — trusting `destination` alone was deliberately rejected, since that would let a corrupted decision silently release a malicious file as clean.
  - Source-deletion failure after a successfully verified and published copy is treated as an **incomplete disposition, not success**: `DispositionError` (stage `source_delete`) is raised, the verified destination copy is kept (not rolled back), the source is left in place (deletion failed), and the exception carries `destination_path` so callers know a verified copy already exists. Directly validated both via a dedicated unit test and a live monkeypatched demonstration outside pytest.
  - Runtime directories live under `/local-data/` (`intake/`, `clean/`, `quarantine/`) at repo root, newly gitignored (`/local-data/`) — never a committed data store. Tests use `tempfile.TemporaryDirectory()`, not the real directory.
  - `tests/test_disposition.py` adds 14 tests (collision refusal, verification-failure preserves source, malformed/unknown/mismatched decisions preserve source, missing source, source-is-a-directory, missing destination directory, source-delete failure, plus all four conclusion → destination routings). Full suite confirmed with real OPA in WSL: **41 passed, 0 skipped**.
  - Not touched: `pipeline.py` (the executor is not yet wired into the pipeline's output), OPA policy, normalizer, schema, Strelka, CI.

## Current phase

**Phase 4 complete: local disposition execution implemented and validated, real-world end-to-end with real OPA.** Next: Phase 5, CAPE integration.

## Current task

None active — awaiting explicit direction to begin Phase 5 (CAPE integration). No CAPE code exists yet.

## Tests currently passing

- `tests/test_strelka_extractor.py`, `tests/test_strelka_normalizer.py`, `tests/test_pipeline.py` (non-OPA cases), `tests/test_disposition.py` — pass unconditionally (install deps via `pip install -r requirements-dev.txt`).
- `tests/test_fileguard_policy.py` and the OPA-dependent tests in `tests/test_pipeline.py` — pass when `opa` is on PATH; confirmed with real OPA 1.19.1 in the developer's WSL environment. Latest full-suite WSL result: **41 passed, 0 skipped**. Tests self-skip via `unittest.skipUnless` when `opa` is not found — an execution environment without `opa` on PATH (e.g. this session's default shell) is an environment difference, not evidence of a defect.

## Known limitations

- OPA policy/pipeline tests are environment-dependent (require `opa` on PATH) and skip silently rather than fail when it's absent.
- The disposition executor is local-only and standalone — not yet wired into `pipeline.py`'s output, and the local directory model (`local-data/intake|clean|quarantine`) is the local equivalent of, not a replacement for, the future AWS S3 copy → verify → delete workflow.
- CAPE, AWS, VirusTotal, and Cuckoo integrations are undesigned beyond the architectural placement described in `docs/ARCHITECTURE.md`.
- ClamAV signature evidence does not yet retain per-child/temporary-file-path attribution — only deduplicated signature names.
- `scanners/`, `kubernetes/thorium/`, and the `verdict`/`scanner-result`/`classifier-result` schemas are legacy artifacts from the pre-Strelka/pre-OPA direction (see `docs/DECISIONS.md`) and should not be extended as if they were current.

## What must NOT be implemented yet

- CAPE integration — do not begin without explicit direction.
- IoCs, notifications.
- S3 disposition execution or any AWS service integration.
- Kubernetes.
- Scaling work of any kind.
- Do not reintroduce Thorium as the current architecture.

## Immediate next step

Begin Phase 5 (CAPE integration) once explicitly approved — no code exists for this phase yet.
