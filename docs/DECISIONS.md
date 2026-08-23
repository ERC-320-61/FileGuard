# FileGuard — Architectural Decisions

Rationale log for major architectural choices. Add new entries at the bottom; don't rewrite history — if a decision is later reversed, add a new entry that supersedes it rather than editing the old one.

## Strelka replaced Thorium

FileGuard's static-analysis framework is Strelka, not Thorium. Thorium has been retired from the current architecture. `kubernetes/thorium/` remains in the tree as a stale directory name from before this pivot (it was created at initial project scaffolding and never renamed) — it is a **legacy artifact**, not a sign that Thorium is still in scope. Do not reintroduce Thorium-based design.

## FileGuard normalizes Strelka output instead of coupling policy directly to Strelka

The OPA policy consumes FileGuard's normalized static evidence (`schemas/static-evidence.schema.json`), not raw Strelka events. This keeps the policy layer stable against changes in Strelka's own output shape, and lets FileGuard define its own status/warning/error semantics (e.g. deciding which Strelka flags count as warnings vs. errors) independent of how Strelka itself reports them.

## UI/API wrapper extraction is separate from raw-event normalization

`extractors/strelka_ui.py` (unwraps the Strelka UI/API `strelka_response` envelope) is a distinct step from `normalizers/strelka.py` (raw event → FileGuard evidence). Keeping these separate means the normalizer can be reused against raw Strelka events from other integration points (not just the UI/API wrapper) without change, and the extractor's only job is understanding one specific envelope format.

## OPA replaces the old custom scoring-engine direction

Disposition decisions are made by an OPA Rego policy (`policies/fileguard/disposition.rego`), not by the custom scoring engine implied by `scanners/scoring-engine/` and `schemas/verdict.schema.json`. The scoring-engine direction (numeric `score`, `verdict: clean/review/malicious`, `action: release/hold/quarantine`) predates the current OPA-based conclusion vocabulary (`CLEAN/SUSPICIOUS/MALICIOUS/INCOMPLETE`) and is a **legacy artifact** — not the current disposition mechanism.

## Fail-closed disposition

Incomplete analysis, scanner failure, or any warning/error that prevents a clean determination must never resolve to `CLEAN`. This is enforced structurally in the policy: the default decision (no rule matched) is `INCOMPLETE`/quarantine, and the `CLEAN` rule requires zero document-level warnings and errors plus every relevant scanner reporting `complete` status. Any future disposition rule must preserve this fail-closed property.

## CAPE is the internal dynamic-analysis layer

CAPE is planned as FileGuard's own internal dynamic-analysis layer for eligible quarantined files, and is explicitly part of the architecture rather than a "maybe later" item. This distinguishes it from VirusTotal and Cuckoo/CuckooBox, which are optional external integrations.

## Legacy custom scanners are retained for future Strelka gap analysis

`scanners/` (capa, clamav, classifier, office-analysis, pdf-analysis, scoring-engine) predates the pivot to Strelka (confirmed by git history: these PoCs were built before the "Pivot static analysis to Strelka" commit). They are kept in the repo intentionally — not as current implementation, but as a reference point for comparing Strelka's coverage against what the custom scanners did, in case gaps need filling later.

## External integrations remain optional and policy-gated

VirusTotal and Cuckoo/CuckooBox are configurable, optional integrations. They must be gated by policy (i.e. their use and their influence on disposition decisions is controlled through OPA, not hardcoded), not treated as required dependencies of the core static or dynamic analysis flow.
