# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, post-approval monitoring, signed governance evidence, change/revalidation control, AI/GenAI overlays, portfolio/third-party risk and deterministic evidence packaging.

Current package boundary: **ModelRiskOps v0.5.0 — Portfolio and Third-Party Model Risk**.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, vendor-safety oracle, outsourcing/compliance decision engine, IAM/KMS product, regulatory certification product, or substitute for independent expert judgement.

## v0.5.0 portfolio and third-party model risk

v0.5 extends the v0.4 AI/GenAI governance boundary with explicit portfolio and third-party dependency evidence:

- append-only, versioned `ThirdPartyProviderProfile` records bind accountable owner plus represented due-diligence, contract, security-assurance and financial-resilience evidence with explicit expiry times;
- `ThirdPartyModelDependency` binds one exact current internal model version to one exact current provider profile and service identity, plus explicit external provider-model identity/version and an exact provider-version evidence digest;
- provider-profile or provider-model/version changes require new dependency evidence rather than being hidden behind a stable service name;
- dependency artifacts carry institution-owned materiality, substitutability and represented data-access level;
- provider-profile drift makes historical dependency evidence stale for current use rather than silently rewriting it;
- `ThirdPartyExitPlan` binds exact dependency evidence to transition, portability and validation evidence; material dependencies require a current exit plan and critical dependencies require represented test evidence under the v0.5 policy contract;
- future exit evidence cannot retroactively make an earlier portfolio assessment complete: plan creation and critical exit testing must be effective no later than the represented assessment time;
- `PortfolioSnapshot` binds the exact current model inventory, exact risk-decision digests, one current version per model and institution-supplied exposure weights totaling exactly **10,000 basis points**;
- concentration logic counts a model's exposure once per provider even when that model uses several services from the same provider, while retaining the separate dependency count;
- `critical_provider_ids` deterministically identifies providers supporting at least one institution-classified critical dependency, without claiming a legal or supervisory critical-provider designation;
- deterministic portfolio assessment reports `healthy`, `degraded`, `breached` or `incomplete`, with fail-closed precedence `incomplete > breached > degraded > healthy`;
- expired due-diligence/contract evidence, missing required exit evidence and exit/test evidence not yet effective at assessment time produce `incomplete` rather than default success;
- institution-owned concentration/high-risk exposure thresholds can produce warning/degraded or breach states without claiming that a provider is objectively unsafe; built-in values are reference/test defaults, not regulatory thresholds;
- exact historical retries remain idempotent after later drift, while current-use checks continue to reject stale provider/dependency/inventory evidence;
- `PortfolioEvidencePackage` binds exact snapshot, policy, assessment, provider, dependency and exit-plan digests and must reproduce offline from current registered evidence;
- strict Draft 2020-12 schemas, adversarial tests, clean-wheel smoke and a dedicated portfolio/third-party CI boundary cover the v0.5 artifacts.

Portfolio weights, dependency materiality, substitutability and provider evidence are institution-supplied governance inputs. ModelRiskOps does not infer economic exposure, vendor solvency, contractual sufficiency, legal outsourcing status, provider safety or regulatory compliance.

See [v0.5 Portfolio and Third-Party Model Risk](docs/PORTFOLIO_THIRD_PARTY.md).

## v0.4.0 AI/GenAI governance overlays retained

The v0.4 boundary remains intact with explicit generative-AI evidence contracts:

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
- GenAI evidence can augment the signed v0.3 change-control/dossier chain without inferring materiality or safety.

Evaluation consumes institution-supplied observations and evidence. ModelRiskOps does not generate ground truth, prescribe universally valid hallucination/fairness/safety metrics, or infer that a provider, corpus, prompt, model or output is safe or legally usable.

## Earlier boundaries retained

- **v0.3 Signed governance and change control:** institution-scoped Ed25519 verification-key records, immutable revocation evidence, exact signed governance envelopes, explicit materiality, signed independent model-change authorization, current revalidation/approval evidence and exact implementation evidence. Private key material remains caller/institution supplied and is never stored by ModelRiskOps.
- **v0.2 Monitoring and drift evidence:** exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds, reference-evidence binding, deterministic latest observations, missing/stale/conflicting evidence handling and `MONITORING_DETERIORATION` revalidation.
- **v0.1 Governance foundation:** immutable institution-scoped model/version inventory, SHA-256 provenance binding, deterministic inherent/residual risk tiering, independent validation, finding remediation, role-bound approvals, bounded exceptions, material-change revalidation and deterministic governance dossiers.

## CLI

After installation:

```bash
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`verify-dossier` performs local integrity verification only; it requires no network access.

## Assurance, signing, AI/GenAI and third-party trust boundary

ModelRiskOps governance decisions, monitoring evidence, signed change-control evidence, GenAI overlays and portfolio/third-party evidence bind to exact model/version and evidence digests. Missing, stale or expired required inputs fail closed where the control requires them.

A valid v0.3 signature proves verification under the represented public key and governed signing scope. It does not itself prove legal authority, external identity, legal non-repudiation, trusted time, external source authenticity or regulator acceptance.

A healthy v0.4 GenAI evaluation means the supplied, current observations satisfied the configured evaluation thresholds. It does **not** establish model safety, factual correctness, hallucination freedom, fairness, privacy compliance, prompt-injection resistance, effective human oversight, legal entitlement, EU AI Act compliance or production fitness.

A healthy v0.5 portfolio assessment means the supplied current provider/dependency/exit evidence satisfies the configured institution-owned thresholds for the represented portfolio weights and assessment time. It does **not** establish vendor safety, financial resilience, outsourcing compliance, contract sufficiency, successful exit capability, objective economic concentration, or a legal designation of provider criticality.

Private-key custody, KMS/HSM integration, trusted timestamping, external immutable anchoring, production IAM, tenant cryptographic isolation and third-party attestation remain later hardening milestones.

## Initial standards posture

Design inputs include:

- Federal Reserve SR 26-2 — Revised Guidance on Model Risk Management (2026), which supersedes SR 11-7;
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1);
- NIST AI 600-1 — Generative AI Profile, including third-party GAI/value-chain risk considerations;
- Regulation (EU) 2024/1689 — EU Artificial Intelligence Act.

These are governance and assurance design inputs, not claims of legal applicability, compliance, supervisory approval, vendor safety or certification.

## Design principles

- Human accountability remains explicit.
- Governance decisions bind to exact model/version and evidence digests rather than mutable names.
- Signed evidence binds represented payloads; it does not replace human authority or production identity controls.
- Foundation-model, prompt, retrieval, provider, provider-model/version, dependency and portfolio metadata are explicit authoritative inputs, not inferred trust decisions.
- GenAI evaluation consumes supplied evidence and never becomes an automatic safety/compliance conclusion.
- Third-party portfolio assessment consumes supplied evidence/weights and never becomes an automatic vendor approval, outsourcing, critical-provider or solvency conclusion.
- Historical evidence is preserved rather than silently overwritten; exact historical retries remain idempotent while current-use validation stays fail-closed.
- Future exit/test evidence cannot be used to satisfy an earlier represented assessment time.
- Private signing keys are never persisted by the governance registry.
- Missing or stale governance, monitoring, signing, GenAI-evaluation, provider, dependency, exit and change-control inputs fail closed where required.
- Change authorization never means ModelRiskOps itself deployed, suspended or replaced a model.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy, call, probe or operate models or providers.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
