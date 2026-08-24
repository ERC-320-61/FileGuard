# FileGuard Architecture

This document describes FileGuard's current and planned components. It reflects the repository as inspected on 2026-08-22 and should be updated as phases complete.

## Static analysis flow (implemented)

```
Strelka UI/API wrapper
  - FileGuard extractor
  - raw Strelka event
  - FileGuard normalizer
  - normalized static evidence
  - OPA policy decision
```

### Strelka — *implemented*

Third-party static-analysis framework. Runs locally (see `strelka/`, a gitignored local clone/dev environment — not tracked repo content). Produces raw scan events via clamav, yara, entropy, and other scanners, wrapped in a `strelka_response` UI/API envelope.

### FileGuard extractor — *implemented*

`extractors/strelka_ui.py`. Responsible for pulling the first raw Strelka event out of the Strelka UI/API response wrapper (`strelka_response` list). Validates wrapper shape and fails loudly (`ValueError`) on malformed input. Deliberately separate from normalization: this layer only knows about the UI/API envelope, not about evidence semantics.

### FileGuard normalizer — *implemented*

`normalizers/strelka.py`. Converts a raw Strelka event into normalized FileGuard static evidence conforming to `schemas/static-evidence.schema.json`. Responsibilities:

- Classifies each scanner's flags/exceptions into `warnings` vs `errors` (scanner-specific rules, e.g. YARA rule-load problems are treated as warnings even when Strelka labels them with "error" text).
- Derives a `status` (`complete` / `incomplete` / `error`) per scanner and for the document as a whole — errors take precedence over warnings, which take precedence over complete.
- Extracts hashes, file metadata, clamav detection, yara matches, entropy, and insights.
- Explicitly omits large/irrelevant scanner-specific fields (verified by test) to keep evidence stable and small.
- Does not mutate the raw input.

### Normalized static evidence — *implemented*

`schemas/static-evidence.schema.json`. The stable contract between the normalizer and the policy layer. `source` is currently pinned to `"strelka"`. This is the schema in active use — see [DECISIONS.md](DECISIONS.md) for why policy is coupled to this normalized shape rather than directly to raw Strelka output.

### OPA — *four-outcome static disposition ruleset implemented*

`policies/fileguard/disposition.rego`, package `fileguard.disposition`. Consumes normalized static evidence and produces a decision object: `{conclusion, destination, review_required, reasons}`.

Conclusion vocabulary: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `INCOMPLETE` — all four implemented as a single deterministic decision chain, evaluated in precedence order:
- **`MALICIOUS`:** clamav complete and detected → quarantine, review required. Takes precedence even over incomplete analysis elsewhere in the same evidence.
- **`INCOMPLETE`:** document status incomplete (and not already `MALICIOUS`) → quarantine, review required.
- **`SUSPICIOUS`:** yara complete with one or more matches, no stronger detection → quarantine, review required.
- **`CLEAN`:** document status complete, clamav complete and not detected, yara complete with zero matches, zero document-level warnings and errors → destination clean, no review required.
- **Default (fail-closed):** no rule matched → `INCOMPLETE`, quarantine, review required.

See [DECISIONS.md](DECISIONS.md) for the precedence rationale.

### Local disposition executor — *implemented (local PoC)*

`disposition.py`. Consumes an OPA decision and a source file path, and executes the resulting disposition against ordinary local directories: `CLEAN → clean/`; `INCOMPLETE`, `SUSPICIOUS`, `MALICIOUS → quarantine/`. Sequence: source SHA-256 → copy to a temp file in the destination directory → destination SHA-256 → compare → atomic no-overwrite publish (`os.link`) → delete source. Fails closed on any malformed/unknown/mismatched decision, destination collision, verification failure, or source-deletion failure (see [DECISIONS.md](DECISIONS.md)). This is the local equivalent of, not a replacement for, the future AWS S3 copy → verify → delete workflow — it is not yet wired into `pipeline.py`'s output.

## Planned components

### CAPE dynamic analysis — *planned, not deferred*

Internal dynamic-analysis layer for files that are quarantined and eligible for further analysis. Explicitly part of the architecture (mentioned in `README.md`), but no integration code exists yet. Distinct from the optional external sandboxing integrations below.

### AWS services — *planned, not implemented*

Target hosting for the production system: S3 (file storage; the local disposition executor above is the local PoC equivalent of the eventual S3 copy → verify → delete workflow), EventBridge/SQS (intake and event routing), ECR/EKS (container hosting), CloudWatch (observability), KMS (key management), DynamoDB (evidence/decision retention). `terraform/` contains only empty placeholder directories (`.gitkeep`) for these services today.

### VirusTotal / Cuckoo (CuckooBox) — *optional, policy-gated, not implemented*

Optional external integrations. Must remain configurable and gated by policy — not hard dependencies of the core static or dynamic flow. No integration code exists yet.

## Legacy / reference components (not part of current architecture)

- `scanners/` — pre-Strelka custom scanner PoCs (capa, clamav, classifier, office-analysis, pdf-analysis, scoring-engine). Retained for future capability comparison / Strelka gap analysis, not part of the current pipeline.
- `kubernetes/thorium/` — stale directory name from the retired Thorium-based plan; predates the pivot to Strelka.
- `schemas/verdict.schema.json`, `schemas/scanner-result.schema.json`, `schemas/classifier-result.schema.json` — modeled around the legacy scanner fleet and a custom scoring-engine verdict shape (`score`, `verdict: clean/review/malicious`, `action: release/hold/quarantine`), which predates and does not match the current OPA conclusion vocabulary (`CLEAN/SUSPICIOUS/MALICIOUS/INCOMPLETE`).

See [DECISIONS.md](DECISIONS.md) for the rationale behind these transitions.
