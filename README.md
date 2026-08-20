# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, monitoring, signed change/revalidation evidence, AI/GenAI overlays, portfolio/third-party risk, framework assurance mappings, tenant/cryptographic hardening and production-reference release evidence.

Current package boundary: **ModelRiskOps v0.8.0 — Production Reference**.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, legal/compliance decision engine, certification product, KMS/HSM product, deployment orchestrator, network-security platform or substitute for independent expert judgement.

## v0.8.0 production reference

v0.8 composes the earlier governance boundaries into an offline production-reference control plane:

- `RuntimeIdentityProfile` binds exact institution/tenant workload identity, service account, issuer/audience evidence and the current v0.7 tenant-isolation profile;
- `HttpsEgressPolicy` is strict default-deny/TLS-only reference evidence with exact DNS hosts, no wildcards and no raw-IP destinations;
- `IsolatedWorkerProfile` requires read-only root filesystem and no-new-privileges while structurally disabling shell, subprocess, privileged-container and model-invocation capabilities;
- `RollbackPlan` binds restore artifact, configuration restore, data-recovery procedure and rollback-validation evidence;
- `UpgradePlan` binds source-release, preflight, migration and post-upgrade evidence to the exact registered rollback plan and requires a backup;
- `RecoveryCheckpoint` binds the exact current tenant-isolation snapshot, backup artifact and recovery-test evidence;
- `DeploymentReleaseManifest` binds exact Git commit, package/wheel, SBOM, CI/provenance, tenant-isolation, runtime-identity, egress, worker, rollback, upgrade and recovery evidence;
- production release manifests require production tenant/runtime profiles, contiguous release sequence and readiness evidence that does not postdate the represented release;
- historical exact release registration remains idempotent after later drift, while `assert_release_current()` revalidates mutable tenant/runtime/egress/worker dependencies and fails closed;
- `assess_release()` yields only `reference_ready` or `ineligible` and never deploys anything;
- eight strict Draft 2020-12 schemas, adversarial tests, Python 3.11/3.12/3.13 clean-wheel CI and a dedicated Production Reference Boundary cover the release.

The release manifest and eligibility assessment structurally fix deployment/execution claims to `false`. A `reference_ready` result therefore means only that the represented current evidence satisfies the v0.8 reference contract; it does **not** prove a live deployment, runtime enforcement, production fitness or regulatory compliance.

See [v0.8 Production Reference](docs/PRODUCTION_REFERENCE.md).

## v0.7.0 tenant and cryptographic hardening retained

The v0.7 boundary remains intact:

- strict institution+tenant PostgreSQL RLS reference policies and versioned tenant-isolation profiles;
- institution-owned KMS/HSM key references for Ed25519 configuration signing and AES-256-GCM evidence encryption;
- no private signing keys or AES key bytes stored by ModelRiskOps;
- monotonic key lifecycle/rotation with no fallback to older keys after newer-version retirement, disablement or expiry;
- exact signed tenant configuration-change chains;
- AES-GCM evidence bound to tenant, isolation profile, key, subject, plaintext digest and authenticated encryption time;
- historical decryptability separated from current-isolation eligibility.

Rendered RLS is not deployed-RLS proof; KMS/HSM references are not hardware-custody proof.

See [v0.7 Tenant and Cryptographic Hardening](docs/TENANT_CRYPTO_HARDENING.md).

## v0.6.0 assurance mappings retained

The v0.6 boundary remains intact with human-confirmed applicability and complete evidence crosswalks for Federal Reserve SR 26-2, NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001:2023 and EU AI Act `2024/1689@2026-07-27`. Required-reference closure prevents favorable-reference cherry-picking, and certification/conformity/legal-compliance/supervisory-acceptance claims remain structurally prohibited.

See [v0.6 Assurance Mappings](docs/ASSURANCE_MAPPINGS.md).

## v0.5.0 portfolio and third-party model risk retained

The v0.5 boundary retains append-only provider profiles, exact model-version/provider dependencies, exit/test evidence, 10,000-bps portfolio snapshots, deterministic concentration/currentness assessment and portfolio evidence packaging. Institution-owned thresholds and evidence do not become automatic vendor-safety or outsourcing/compliance conclusions.

See [v0.5 Portfolio and Third-Party Model Risk](docs/PORTFOLIO_THIRD_PARTY.md).

## v0.4.0 AI/GenAI governance overlays retained

The v0.4 boundary retains exact foundation-model, prompt/system-policy, RAG, use-case, evaluation, human-oversight and revalidation evidence. Evaluation consumes institution-supplied observations and never becomes an automatic safety/compliance conclusion.

## Earlier boundaries retained

- **v0.3 Signed governance and change control:** Ed25519 verification-key evidence, signed governance envelopes, explicit materiality, signed change authorization and exact implementation evidence.
- **v0.2 Monitoring and drift evidence:** exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds and deterministic latest observations.
- **v0.1 Governance foundation:** immutable model/version inventory, SHA-256 provenance binding, deterministic risk tiering, independent validation, role-bound approval, bounded exception and revalidation evidence.

## CLI

After installation:

```bash
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`verify-dossier` performs local integrity verification only; it requires no network access.

## Trust boundary

ModelRiskOps binds governance artifacts to exact identities, versions and evidence digests. Missing, stale, expired or incomplete required inputs fail closed where the corresponding control requires them.

A valid signature proves verification under the represented public key and signing scope; it does not itself prove legal authority, trusted time, external-source authenticity or regulator acceptance.

A healthy GenAI evaluation does not establish model safety, factual correctness, fairness, privacy compliance or prompt-injection resistance. A healthy portfolio assessment does not establish vendor safety, solvency, outsourcing compliance or successful exit capability. A v0.6 `supported` crosswalk entry does not establish legal satisfaction or conformity. A v0.7 RLS/key artefact does not prove live enforcement or hardware custody.

A v0.8 `reference_ready` assessment does not establish that a deployment occurred or that Kubernetes, IAM, network, database, KMS/HSM, backup, recovery, SBOM or provenance controls are operating effectively. Those remain institution-owned production responsibilities.

## Standards posture

Current design inputs/framework identities include:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management** (17 April 2026), superseding SR 11-7;
- NIST **AI Risk Management Framework 1.0**;
- NIST **AI 600-1 — Generative AI Profile**;
- ISO/IEC **42001:2023**; and
- Regulation (EU) **2024/1689**, represented against consolidated EUR-Lex revision `2024/1689@2026-07-27`.

These are architecture and assurance inputs, not claims of legal applicability, compliance, supervisory approval, conformity or certification.

## Design principles

- Human accountability and applicability decisions remain explicit.
- Governance decisions bind exact model/version/evidence identities rather than mutable names.
- Historical evidence is immutable; current-use validation is separate and fail closed.
- Future evidence cannot satisfy an earlier represented governance or release time.
- Secret key material is not serialized by governance registries.
- Production-reference network and worker policies are default-deny/non-executing contracts, not runtime enforcement claims.
- Release readiness requires exact rollback, upgrade and recovery evidence.
- Regulatory mappings remain separate from legal conclusions and certification claims.
- The governance core does not train, deploy, call, probe, score or operate models, providers, networks, databases, KMS/HSM systems or deployment platforms.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
