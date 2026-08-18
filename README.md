# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, and AI models through a controlled lifecycle: inventory, risk classification, independent validation, approval, post-approval monitoring, signed governance evidence, change/revalidation control, and deterministic evidence packaging.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, IAM/KMS product, regulatory certification product, or substitute for independent expert judgement.

## v0.3.0 signed governance and change control

ModelRiskOps v0.3.0 extends the v0.2 monitoring/drift foundation with institution-scoped cryptographic verification and explicit model-change authorization:

- Ed25519 public verification-key records with key identity, accountable owner, permitted governance roles, validity window and immutable revocation evidence;
- caller/institution-supplied private key material is used only transiently for signing and is never stored in ModelRiskOps artifacts or registries;
- signed governance envelopes bind the exact canonical artifact payload, artifact digest, institution/model/version scope, signer identity, signer role, key identity, signing purpose and signing time;
- offline signature verification fails closed for wrong scope, wrong key content, unauthorized role, tampered payload, mismatched private/public key, invalid signature, not-yet-valid/expired keys and current use of revoked keys;
- historical signature verification preserves evidence that was valid at signing time, while current-use verification can additionally require the key to remain active at evaluation time;
- explicit `material` / `non_material` model-change proposals bind exact before/after model record, model version and risk-policy state plus derived revalidation evidence where applicable;
- materiality remains an accountable institutional decision and is not silently inferred solely from which fields changed;
- material changes require at least two independent authorization roles, signed authorization votes, current revalidation evidence and a current approved after-state validation/approval chain;
- materiality decision owners cannot authorize their own change, and distinct required authorization roles require distinct people;
- incomplete or rejected authorization packages cannot be represented as authorized;
- implementation evidence binds the exact authorized after-state and explicitly does **not** mean ModelRiskOps executed deployment;
- signed change-control evidence can be added to the deterministic governance dossier through a typed hardened helper that re-verifies signatures and exact artifact bindings;
- strict Draft 2020-12 schemas cover verification keys, revocations, signed envelopes, change proposals, authorization artifacts and implementation evidence;
- Python 3.11/3.12/3.13 CI, wheel build and clean-installed-wheel smoke tests remain part of the release gate.

## v0.2.0 monitoring and drift evidence retained

The v0.2 contracts remain intact: exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds, reference-evidence digest binding, deterministic latest-observation selection, missing/stale/conflicting evidence handling, healthy/degraded/breached/incomplete monitoring states and deterministic `MONITORING_DETERIORATION` revalidation paths.

Monitoring evidence remains governance evidence over already-computed metrics. It does not infer statistical validity from raw production data and does not prescribe one universal drift statistic or fairness metric across institutions and use cases.

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

## Assurance, signing and trust boundary

ModelRiskOps governance decisions, monitoring evidence and signed change-control evidence bind to exact model/version and evidence digests. Missing or stale required inputs fail closed where the control requires them.

v0.3.0 adds **offline cryptographic signature verification inside the represented institution-owned key/role registry**. A valid signature proves that the represented payload verifies under the represented public key and governed signing scope. It does not by itself prove legal authority, employment/identity outside that registry, legal non-repudiation, trusted time, external source authenticity or regulator acceptance.

Private-key custody, KMS/HSM integration, trusted timestamping, external immutable anchoring, production IAM, tenant cryptographic isolation and third-party attestation remain later hardening milestones. Those concerns are deliberately not implied by v0.3 signing support.

Registration, risk classification, validation, approval, monitoring assessment, signature verification, change authorization or dossier generation does not itself establish that a model is safe, unbiased, lawful, compliant, statistically valid, fit for production, fit for continued operation, or accepted by a regulator.

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
- Signed evidence binds represented payloads; it does not replace human authority or production identity controls.
- Private signing keys are never persisted by the governance registry.
- Missing or stale governance, monitoring, signing and change-control inputs fail closed where required.
- Historical evidence is preserved rather than silently overwritten.
- Exceptions do not silently replace mandatory validation paths.
- Monitoring deterioration creates accountable governance work; it does not autonomously change model lifecycle state.
- Change authorization never means ModelRiskOps itself deployed, suspended or replaced a model.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy or operate models.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
