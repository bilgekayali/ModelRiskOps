# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, and AI models through a controlled lifecycle: inventory, risk classification, independent validation, approval, post-approval monitoring, change/revalidation control, and evidence packaging.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, regulatory certification product, or substitute for independent expert judgement.

## v0.2.0 monitoring and drift evidence

ModelRiskOps v0.2.0 extends the v0.1 governance foundation with deterministic post-approval monitoring contracts:

- monitoring plans bound to the exact `ModelVersion` and `RiskDecision` digests;
- standard and risk-derived enhanced monitoring levels;
- closed metric taxonomy for performance, data drift, prediction drift, calibration, fairness, stability and operational signals;
- warning/breach thresholds with explicit direction semantics and minimum sample requirements;
- exact reference-evidence digest binding for data/prediction drift baselines;
- monitoring observations bound to plan digest, metric identity, evidence window, observation time, sample size and source-evidence digest;
- deterministic latest-observation selection independent of input order;
- fail-closed handling of missing, stale, insufficient-sample, unknown-plan and conflicting-latest evidence;
- healthy, degraded, breached and incomplete monitoring states;
- breached or incomplete monitoring evidence deterministically creates a `MONITORING_DETERIORATION` revalidation path;
- no automatic lifecycle mutation, deployment, suspension or model approval from monitoring state;
- strict Draft 2020-12 JSON Schemas for monitoring plans, observations and assessments;
- Python 3.11/3.12/3.13 CI, wheel build and clean-installed-wheel smoke tests.

The monitoring core governs already-computed metrics and their evidence. v0.2.0 does not infer statistical validity from raw production data and does not prescribe one universal drift statistic or fairness metric across institutions and use cases.

## v0.1.0 governance foundation retained

The v0.1 contracts remain intact: immutable institution-scoped model/version inventory, SHA-256 provenance binding, deterministic inherent/residual risk tiering, independent validation, finding remediation, role-bound approvals, bounded exceptions, material-change revalidation, deterministic governance dossiers, offline integrity verification and strict release schemas.

## CLI

After installation:

```bash
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`verify-dossier` performs local integrity verification only; it requires no network access.

## Assurance and integrity boundary

ModelRiskOps governance decisions and monitoring evidence bind to exact model/version, risk-policy, validation, approval and monitoring evidence. Missing or stale required inputs fail closed where the control requires them.

The project provides **deterministic integrity and internal-consistency evidence**, not source authenticity or non-repudiation. v0.2.0 does not yet provide institution-owned signing keys, external immutable anchoring, trusted timestamping, production identity/IAM, production telemetry collection or independent third-party attestation. Those remain later hardening milestones.

Registration, risk classification, validation, approval, monitoring assessment or dossier generation does not itself establish that a model is safe, unbiased, lawful, compliant, statistically valid, fit for production, fit for continued operation, or accepted by a regulator.

## Initial standards posture

Design inputs include:

- Federal Reserve SR 26-2 — Revised Guidance on Model Risk Management (2026), which supersedes SR 11-7;
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1);
- NIST AI 600-1 — Generative AI Profile;
- Regulation (EU) 2024/1689 — EU Artificial Intelligence Act.

These are governance and assurance design inputs, not claims of legal applicability, compliance, supervisory approval, model safety or certification.

## Design principles

- Human accountability remains explicit.
- Governance decisions bind to exact model/version and evidence digests rather than mutable names.
- Missing or stale governance and monitoring inputs fail closed where required.
- Historical evidence is preserved rather than silently overwritten.
- Exceptions do not silently replace mandatory validation paths.
- Monitoring deterioration creates accountable governance work; it does not autonomously change model lifecycle state.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy or operate models.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
