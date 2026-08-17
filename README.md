# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, and AI models through a controlled lifecycle: inventory, risk classification, independent validation, approval, change/revalidation control, and evidence packaging.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, regulatory certification product, or substitute for independent expert judgement.

## v0.1.0 foundation

ModelRiskOps v0.1.0 provides an executable governance-control foundation with:

- immutable institution-scoped model records and exact model-version provenance;
- artifact, code, data and configuration SHA-256 bindings;
- explicit dataset, system, vendor, foundation-model and critical-service dependencies;
- deterministic canonical JSON and evidence digests;
- closed lifecycle transitions and conflicting model/version reuse protection;
- deterministic inherent/residual risk tiering from nine closed risk factors;
- institution/policy-digest binding, bounded control credit and tier-derived governance requirements;
- independent validation plans bound to the exact model version and risk decision;
- structured validation tests/findings, remediation evidence and independent closure;
- fail-closed handling of incomplete mandatory tests and unresolved high/critical findings;
- role-bound approval requirements with distinct-person enforcement for critical multi-role approvals;
- approve, approve-with-conditions, reject and incomplete approval resolutions;
- bounded exception artifacts with exact scope, compensating controls, expiry and optional one-time semantics;
- deterministic revalidation requirements for material model, data, configuration, dependency, business-use, policy and operational-control changes;
- a self-contained governance dossier that re-resolves validation findings and approval votes before packaging;
- canonical artifact payloads, per-artifact digests and a deterministic dossier manifest digest;
- offline dossier verification and tamper detection;
- strict Draft 2020-12 JSON Schemas for inventory, risk, validation, approval, exception, revalidation and dossier artifacts;
- Python 3.11/3.12/3.13 CI, wheel build and clean-installed-wheel smoke tests.

## CLI

After installation:

```bash
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`verify-dossier` performs local integrity verification only; it requires no network access.

## Assurance and integrity boundary

ModelRiskOps governance decisions bind to exact model/version, risk-policy, validation and approval evidence. Missing or stale inputs fail closed where the control requires them, and a material revalidation trigger prevents an existing dossier from representing a complete governance path.

The v0.1.0 dossier provides **deterministic integrity and internal-consistency evidence**, not source authenticity or non-repudiation. It does not yet provide institution-owned signing keys, external immutable anchoring, trusted timestamping, production identity/IAM, or independent third-party attestation. Those are later hardening milestones.

Registration, risk classification, validation, approval or dossier generation does not itself establish that a model is safe, unbiased, lawful, compliant, fit for production, or accepted by a regulator.

## Initial standards posture

Design inputs include:

- Federal Reserve SR 26-2 — Revised Guidance on Model Risk Management (2026), which supersedes SR 11-7;
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1);
- NIST AI 600-1 — Generative AI Profile;
- Regulation (EU) 2024/1689 — EU Artificial Intelligence Act.

These are governance and assurance design inputs, not claims of legal applicability, compliance, supervisory approval, model safety, or certification.

## Design principles

- Human accountability remains explicit.
- Governance decisions bind to exact model/version and evidence digests rather than mutable names.
- Missing or stale governance inputs fail closed where required.
- Historical evidence is preserved rather than silently overwritten.
- Exceptions do not silently replace mandatory validation paths.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train or deploy models.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
