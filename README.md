# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, monitoring, signed change/revalidation evidence, AI/GenAI overlays, portfolio/third-party risk, framework assurance mappings, tenant-isolation metadata and cryptographic governance evidence.

Current package boundary: **ModelRiskOps v0.7.0 — Tenant and Cryptographic Hardening**.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, legal/compliance decision engine, certification product, KMS/HSM product, database security product, regulator gateway or substitute for independent expert judgement.

## v0.7.0 tenant and cryptographic hardening

v0.7 extends the v0.6 evidence/control plane with explicit tenant and cryptographic hardening contracts:

- `PostgresRlsPolicy` represents strict institution+tenant PostgreSQL RLS predicates and renders reference DDL with both `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`;
- SQL identifiers and `modelriskops.*` session settings are syntactically constrained before rendering;
- `TenantIsolationProfile` binds institution/tenant identity, governed environment, database role, namespace digest and exact current RLS policy digests;
- RLS policies and isolation profiles are append-only/version-contiguous; historical exact retries remain idempotent while stale policies/profiles fail current-use validation;
- `InstitutionCryptoKeyReference` represents institution-owned KMS/HSM key metadata for Ed25519 configuration signing or AES-256-GCM evidence encryption;
- private signing keys and AES key bytes are never stored; AES references structurally reject embedded symmetric key material;
- key versions are contiguous, rotated versions require distinct `key_id` values, and lifecycle transitions are limited to `active -> retired|disabled` and `retired -> disabled`;
- new cryptographic operations use the **latest eligible key version only**, preventing rollback to an older active key after a newer key is retired or disabled;
- `ConfigurationChangeRequest` + `SignedConfigurationChange` form an exact tenant-scoped Ed25519 change chain with sequence, previous-change digest, configuration digests, human requester identity and effective-time controls;
- configuration evidence cannot become current before `effective_at`, cannot fork the exact change chain and is not automatically applied to any external system;
- `EncryptedGovernanceEvidence` binds AES-256-GCM ciphertext to exact tenant, isolation profile, key reference and subject-artifact digests through canonical AAD and a fresh 96-bit nonce;
- historical encrypted evidence remains decryptable against exact historical registered metadata when the key is not disabled, while `assert_encrypted_evidence_current()` separately fails closed after isolation drift or key disablement;
- seven strict Draft 2020-12 schemas, adversarial tests, Python 3.11/3.12/3.13 clean-wheel CI and a dedicated Tenant and Cryptographic Hardening Boundary cover the release.

RLS rendering is reference output, not deployed-RLS proof. KMS/HSM references are governance metadata, not hardware-custody or attestation proof. Cryptographic operations are performed only through caller/institution-supplied signer/encryptor/decryptor interfaces whose identities must match the exact registered key references.

See [v0.7 Tenant and Cryptographic Hardening](docs/TENANT_CRYPTO_HARDENING.md).

## v0.6.0 assurance mappings retained

The v0.6 boundary remains intact:

- `AssuranceMappingProfile` defines an institution-owned, versioned required-reference catalog for one exact supported framework version and binds the source catalog/document digest;
- supported framework identities are Federal Reserve SR 26-2, NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001:2023 and the EU AI Act consolidated revision represented as `2024/1689@2026-07-27`;
- applicability is explicit human evidence, including human-confirmed EU AI Act operator roles;
- package construction is closed over every required reference, preventing favorable-reference cherry-picking;
- mapping-profile drift preserves historical package verification while current-use validation fails closed;
- coverage labels/counts are evidence classifications, not compliance scores;
- certification, conformity, legal-compliance and supervisory-acceptance claims are structurally prohibited.

See [v0.6 Assurance Mappings](docs/ASSURANCE_MAPPINGS.md).

## v0.5.0 portfolio and third-party model risk retained

The v0.5 boundary remains intact:

- append-only provider profiles bind represented due-diligence, contract, security-assurance and financial-resilience evidence with explicit expiries;
- exact model-version → provider/service dependencies bind provider model/version evidence, materiality, substitutability and data-access level;
- provider/model-version changes require new dependency evidence rather than hiding behind stable names;
- material dependencies require current exit evidence and critical dependencies require represented exit-test evidence;
- future exit/test evidence cannot retroactively satisfy an earlier assessment;
- portfolio positions total exactly 10,000 basis points and provider concentration counts each model exposure once per provider;
- deterministic states are `healthy`, `degraded`, `breached`, `incomplete` with fail-closed precedence;
- historical retries remain immutable/idempotent while stale provider/dependency/inventory evidence fails current-use checks.

See [v0.5 Portfolio and Third-Party Model Risk](docs/PORTFOLIO_THIRD_PARTY.md).

## v0.4.0 AI/GenAI governance overlays retained

The v0.4 boundary remains intact with exact foundation-model, prompt/system-policy, RAG, use-case, evaluation, human-oversight and revalidation evidence. Evaluation consumes institution-supplied observations and never becomes an automatic safety/compliance conclusion. GenAI evidence can augment the signed v0.3 change-control/dossier chain without inferring materiality or safety.

## Earlier boundaries retained

- **v0.3 Signed governance and change control:** institution-scoped Ed25519 verification keys, immutable revocation evidence, exact signed governance envelopes, explicit materiality, signed independent model-change authorization, current revalidation/approval evidence and exact implementation evidence. Private signing keys remain caller/institution supplied and are never persisted by ModelRiskOps.
- **v0.2 Monitoring and drift evidence:** exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds, deterministic latest observations, missing/stale/conflicting evidence handling and `MONITORING_DETERIORATION` revalidation.
- **v0.1 Governance foundation:** immutable institution-scoped model/version inventory, SHA-256 provenance binding, deterministic inherent/residual risk tiering, independent validation, finding remediation, role-bound approvals, bounded exceptions, material-change revalidation and deterministic governance dossiers.

## CLI

After installation:

```bash
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`verify-dossier` performs local integrity verification only; it requires no network access.

## Trust boundary

ModelRiskOps binds governance and assurance artifacts to exact model/version and evidence digests. Missing, stale, expired or incomplete required inputs fail closed where the corresponding control requires them.

A valid signature proves verification under the represented public key and signing scope; it does not itself prove legal authority, trusted time, external-source authenticity or regulator acceptance.

A healthy GenAI evaluation does not establish model safety, factual correctness, fairness, privacy compliance or prompt-injection resistance.

A healthy portfolio assessment does not establish vendor safety, solvency, outsourcing compliance, contract sufficiency, successful exit capability or objective economic concentration.

A v0.6 `supported` crosswalk entry means only that a human mapper represented exact evidence as support for one exact reference. It does **not** establish legal satisfaction, conformity, certification, operating effectiveness or supervisory acceptance.

A v0.7 tenant-isolation profile and rendered RLS policy do **not** prove live tenant isolation. A KMS/HSM key reference does **not** prove hardware custody or non-exportability. An encrypted evidence envelope proves only the represented cryptographic binding under the caller-supplied cryptographic interface and exact registered metadata.

Actual production PostgreSQL enforcement, cloud IAM, KMS/HSM custody/attestation, secret management, network isolation, trusted timestamping, external immutable anchoring, release provenance, recovery and production operational controls remain external responsibilities and/or v0.8 production-reference work.

## Standards posture

Current design inputs/framework identities include:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management** (17 April 2026), which supersedes SR 11-7;
- NIST **AI Risk Management Framework 1.0** (NIST AI 100-1);
- NIST **AI 600-1 — Generative AI Profile**;
- ISO/IEC **42001:2023**; and
- Regulation (EU) **2024/1689** — EU Artificial Intelligence Act, with the current consolidated EUR-Lex revision represented by v0.6/v0.7 as `2024/1689@2026-07-27`.

These are architecture and assurance inputs, not claims of legal applicability, compliance, supervisory approval, vendor safety, conformity or certification.

## Design principles

- Human accountability and applicability decisions remain explicit.
- Governance decisions bind to exact model/version and evidence digests rather than mutable names.
- Framework mapping profiles are institution-owned, versioned and source-digest bound.
- Assurance packaging is complete over the declared required-reference catalog; favorable-reference cherry-picking fails closed.
- Tenant isolation metadata is append-only/versioned and currentness is distinct from historical evidence.
- Key rotation is monotonic for new operations; older key versions never regain current status by fallback.
- Secret key material is not serialized by the governance registry.
- Historical encrypted evidence remains reproducible/decryptable independently from current-isolation eligibility.
- Future evidence cannot satisfy an earlier represented governance time.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy, call, probe or operate models, providers, regulators, standards services, databases, KMS or HSM systems.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
