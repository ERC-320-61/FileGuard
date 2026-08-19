# FileGuard

FileGuard is a proof-of-concept secure file intake and malware analysis platform designed to grow into an AWS-hosted system. The planned architecture uses Amazon S3, EventBridge, SQS, ECR, EKS with EC2 worker nodes, CloudWatch, KMS, Thorium, and Dockerized scanners for file classification, ClamAV, YARA, capa, Office documents, PDFs, and verdict scoring.

## Project layout

- `docs/` — architecture and container documentation.
- `terraform/` — future infrastructure modules, grouped by AWS service.
- `kubernetes/` — Kubernetes and Thorium deployment configuration.
- `scanners/` — isolated Docker build contexts for analysis components.
- `rules/` — YARA rules grouped by source and urgency.
- `pipelines/` — file-intake workflow definitions.
- `schemas/` — shared JSON result and verdict contracts.
- `scripts/` — image build, push, and local development helpers.
- `samples/` — local-only test sample locations.

> **Warning:** Never commit malware samples, secrets, credentials, private keys, or sensitive analysis output to this repository.
