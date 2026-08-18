# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, post-approval monitoring, signed governance evidence, change/revalidation control, AI/GenAI overlays and deterministic evidence packaging.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, AI-safety oracle, IAM/KMS product, regulatory certification product, or substitute for independent expert judgement.

## v0.4.0 AI/GenAI governance overlays

ModelRiskOps v0.4.0 extends the v0.3 signed-governance/change-control boundary with explicit generative-AI evidence contracts:

- foundation-model dependency records bind provider/model/version/deployment identity, accountable owner, artifact/config digests and represented terms/license evidence;
- versioned prompt/system-policy artifacts bind exact prompt and safety-policy digests, intended purpose and prohibited behaviors;
- RAG configuration evidence binds corpus/version, index, embedding model/version, chunking policy, retrieval policy, source-set digest and citation requirement;
- GenAI use-case profiles explicitly define intended users, prohibited uses, output handling, human-review requirements, high-impact use status and permitted tool actions;
- deterministic overlay snapshots bind exact foundation-model, prompt-policy, RAG and use-case evidence to one institution/model/version;
- evaluation plans govern already-produced factuality, groundedness, harmful-content, prompt-injection, privacy-leakage, fairness/bias, tool-control and operational-robustness metrics;
- evaluation observations are bound to exact plan digest, metric identity, sample size, observation time and source-evidence digest;
- missing, stale, insufficient-sample and conflicting-latest evaluation evidence fails closed as `incomplete`; threshold breach produces `breached`, warnings produce `degraded`;
- human-oversight requirements and decisions are explicit evidence; a use case that already requires review cannot be weakened by a later oversight artifact;
- GenAI-specific revalidation evidence records explicit foundation-model, prompt-policy, retrieval-corpus, embedding-model, tool-scope and safety-policy triggers;
- `create_genai_model_change_proposal` binds exact before/after GenAI overlay digests into the existing v0.3 `ModelChangeProposal` / `RevalidationRequirement` authorization chain without inferring materiality;
- GenAI evidence can augment an existing governance or signed-change dossier through a typed helper; breached/incomplete evaluation or escalated/rejected oversight fails closed in dossier state;
- strict Draft 2020-12 schemas and Python 3.11/3.12/3.13 wheel/clean-wheel release gates cover the v0.4 artifacts.

Evaluation consumes institution-supplied observations and evidence. ModelRiskOps does not generate ground truth, prescribe a universally valid hallucination/fairness/safety metric, or infer that a provider, corpus, prompt, model or output is safe or legally usable.

## v0.3.0 signed governance and change control retained

The v0.3 contracts remain intact: institution-scoped Ed25519 public verification-key records, immutable revocation evidence, exact signed governance envelopes, historical-versus-current key validity, explicit materiality, signed independent model-change authorization, current revalidation/approval evidence and exact implementation evidence. Private key material remains caller/institution supplied and is never stored by ModelRiskOps.

## v0.2.0 monitoring and drift evidence retained

The v0.2 contracts remain intact: exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds, reference-evidence digest binding, deterministic latest-observation selection, missing/stale/conflicting evidence handling, healthy/degraded/breached/incomplete monitoring states and deterministic `MONITORING_DETERIORATION` revalidation paths.

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

## Assurance, signing and AI/GenAI trust boundary

ModelRiskOps governance decisions, monitoring evidence, signed change-control evidence and GenAI overlays bind to exact model/version and evidence digests. Missing or stale required inputs fail closed where the control requires them.

A valid v0.3 signature proves verification under the represented public key and governed signing scope. It does not itself prove legal authority, external identity, legal non-repudiation, trusted time, external source authenticity or regulator acceptance.

A healthy v0.4 GenAI evaluation means the supplied, current observations satisfied the configured evaluation thresholds. It does **not** establish model safety, factual correctness, hallucination freedom, fairness, absence of harmful content, privacy compliance, prompt-injection resistance, effective human oversight, legal entitlement to use a foundation model/corpus, EU AI Act compliance, production fitness or supervisory acceptance.

Private-key custody, KMS/HSM integration, trusted timestamping, external immutable anchoring, production IAM, tenant cryptographic isolation and third-party attestation remain later hardening milestones.

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
- Foundation-model, prompt, retrieval and tool metadata are explicit authoritative inputs, not inferred trust decisions.
- GenAI evaluation consumes supplied evidence and never becomes an automatic safety/compliance conclusion.
- Human-oversight evidence records represented review state; it does not prove review quality.
- Private signing keys are never persisted by the governance registry.
- Missing or stale governance, monitoring, signing, GenAI-evaluation and change-control inputs fail closed where required.
- Historical evidence is preserved rather than silently overwritten.
- Change authorization never means ModelRiskOps itself deployed, suspended or replaced a model.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy or operate models.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
