# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, and AI models through a controlled lifecycle: inventory, risk classification, independent validation, approval, monitoring, change control, and retirement.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, regulatory certification product, or substitute for independent expert judgement.

## Purpose

Model risk is not limited to model accuracy. Institutions need to know which models exist, who owns and validates them, how material they are, what evidence supports approval, when they changed, whether limitations remain open, and when revalidation is required.

ModelRiskOps turns those governance relationships into deterministic, machine-readable evidence bound to exact model versions and policy state.

## Current implementation — v0.1 foundation

The current foundation provides:

- immutable, institution-scoped model records and exact model-version provenance bound to artifact, code, data and configuration SHA-256 digests;
- explicit dependency references for datasets, systems, vendors, foundation models and critical services;
- deterministic canonical JSON, evidence digests and strict machine-readable schemas;
- closed lifecycle transitions and conflicting model/version reuse protection;
- deterministic inherent/residual model-risk tiering from nine closed risk factors;
- institution/policy-digest binding, bounded control credit and tier-derived governance requirements;
- independent validation plans bound to the exact model version and risk decision;
- structured validation tests and findings with segregation-of-duties controls;
- fail-closed resolution semantics for incomplete mandatory tests and unresolved high/critical findings;
- remediation evidence plus independent validator closure before findings can become closed;
- role-bound approval requirements derived from current risk and validation state;
- distinct-person approval enforcement for multi-role critical-risk decisions;
- explicit approve, approve-with-conditions, reject and incomplete approval states;
- bounded exception artifacts with exact scope, compensating controls, expiry and optional one-time semantics;
- deterministic revalidation requirements for material model, data, configuration, dependency, business-use, policy or operational-control changes;
- stale approval/exception protection through exact model-version, risk, validation and policy digest binding;
- Python 3.11/3.12/3.13 CI plus clean-wheel smoke testing.

The final deterministic governance dossier and complete schema/release gate remain the last v0.1 milestone. Registration, risk classification, validation evidence or a partial approval package alone does not authorize deployment.

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
- Missing or stale security/governance inputs fail closed where the control requires them.
- Historical evidence is preserved rather than silently overwritten.
- Exceptions cannot silently replace mandatory validation or accountable approval paths.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The core governance library does not execute, train or deploy models.

## Roadmap direction

`v0.1 governance foundation (inventory/provenance → risk tiering → independent validation → approval/revalidation → deterministic dossier) → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
