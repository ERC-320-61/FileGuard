# FileGuard

FileGuard is a proof-of-concept secure file intake and malware analysis platform designed to grow into an AWS-hosted system.

The current architecture uses Strelka for static file analysis, a FileGuard normalization layer for producing stable evidence, Open Policy Agent (OPA) for policy-based disposition decisions, and CAPE for isolated dynamic analysis of quarantined files.

The planned AWS architecture uses Amazon S3, EventBridge, SQS, ECR, EKS, EC2, CloudWatch, KMS, and DynamoDB to support file intake, analysis, disposition, evidence retention, and IoC storage.

## Project layout

- `docs/` — architecture and project documentation.
- `terraform/` — future AWS infrastructure modules.
- `kubernetes/` — future Kubernetes deployment configuration.
- `scanners/` — legacy/custom scanner implementations retained for capability comparison and future Strelka gap analysis.
- `strelka/` — local Strelka development environment.
- `extractors/` — extraction of raw analysis events from integration-specific wrappers.
- `normalizers/` — conversion of analysis results into stable FileGuard evidence.
- `rules/` — YARA and future analysis rules.
- `policies/` — future OPA policy definitions.
- `schemas/` — FileGuard evidence and decision schemas.
- `tests/` — unit tests and reconstructed/real analysis fixtures.
- `scripts/` — build and local development helpers.
- `samples/` — local-only test sample locations.

> **Warning:** Never commit malware samples, secrets, credentials, private keys, controlled information, or sensitive analysis output to this repository.