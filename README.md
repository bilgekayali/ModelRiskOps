# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, monitoring, signed change/revalidation evidence, AI/GenAI overlays, portfolio/third-party risk, framework assurance mappings, tenant/cryptographic hardening and production-reference release evidence.

Current source boundary: **ModelRiskOps v1.0.0 — Stable Governance Reference**.

The `v1.0.0` package/API contract can be developed and merged before the formal stable tag is issued. The stable tag remains fail-closed until a genuine independent security review for the exact reviewed repository state is committed at `security-review/v1.0-review.json`.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, legal/compliance decision engine, certification product, KMS/HSM product, deployment orchestrator, network-security platform, regulator gateway or substitute for independent expert judgement.

## v1.0.0 stable governance reference

v1.0 introduces an explicit compatibility and release-governance boundary over the retained v0.1-v0.8 controls:

- the stable Python API is deliberately limited to symbols exported by `modelriskops.api`;
- the stable CLI consists of `contract-snapshot`, `digest-json`, `validate-schema` and `verify-dossier`;
- `compatibility/v1-public-api.json` freezes the stable Python/CLI surface;
- `compatibility/v1-schema-baseline.json` freezes the complete JSON-schema file set present at the v1 baseline;
- `StableCompatibilityPolicy` requires Semantic Versioning and treats removal of stable Python symbols, CLI commands, schemas, required JSON fields or enum values as major-version changes;
- `SupportedUpgradePath` binds the exact historical `0.8.x` source release and exact current `1.0.0` target release plus preflight, migration, post-upgrade, rollback and backup evidence;
- `StableReleaseBaseline` binds compatibility, public-surface, production-reference, upgrade, review, responsibility, checksum/provenance and all eight governance-boundary evidence references;
- historical baseline registration is immutable/idempotent while current eligibility separately revalidates the exact target release and upgrade bindings;
- `IndependentSecurityReviewChecklist` requires 12 canonical items, explicit reviewer independence and item-level evidence/rationale; residual risk requires explicit accountable-human acceptance evidence;
- the independent review binds `reviewed_repository_digest`, a deterministic SHA-256 over all tracked repository content except the final review JSON itself;
- the `v1.0.0` tag workflow recomputes that repository digest before GitHub artifact attestation, preventing a reviewed source tree from being changed silently after review;
- responsibility/non-claim contracts keep legal compliance, certification, supervisory acceptance, model safety and production fitness outside automated conclusions.

See [Compatibility](docs/COMPATIBILITY.md), [Stable Release](docs/STABLE_RELEASE.md), [v1 Upgrade](docs/UPGRADE_V1.md), and [Security Review](docs/SECURITY_REVIEW.md).

## v0.8.0 production reference retained

The v0.8 boundary remains intact:

- `RuntimeIdentityProfile` binds exact institution/tenant runtime identity to current tenant-isolation evidence;
- `HttpsEgressPolicy` is strict default-deny/TLS-only reference evidence with exact DNS hosts, no wildcards and no raw-IP destinations;
- `IsolatedWorkerProfile` requires read-only root filesystem and no-new-privileges while disabling shell, subprocess, privileged-container and model-invocation capabilities;
- rollback, upgrade and recovery artefacts are exact digest-bound release prerequisites;
- `DeploymentReleaseManifest` binds Git commit, package/wheel, SBOM, CI/provenance, tenant isolation, identity, egress, worker, rollback, upgrade and recovery evidence;
- release identities are append-only and cannot be reused; readiness evidence cannot postdate the represented release;
- historical releases remain reproducible while mutable currentness checks fail closed after isolation/runtime/egress/worker drift;
- release eligibility is only `reference_ready` or `ineligible`, and deployment/model execution claims are structurally false.

A `reference_ready` result is evidence-contract status only; it does not prove live deployment or runtime enforcement.

See [v0.8 Production Reference](docs/PRODUCTION_REFERENCE.md).

## Earlier boundaries retained

- **v0.7 Tenant & cryptographic hardening:** strict PostgreSQL RLS reference policies, tenant-isolation profiles, institution-owned KMS/HSM key references, monotonic key lifecycle, signed configuration-change chains and AES-256-GCM evidence binding. Rendered RLS is not deployed-RLS proof; key references are not hardware-custody proof.
- **v0.6 Assurance mappings:** human-confirmed applicability and complete crosswalks for Federal Reserve SR 26-2, NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001:2023 and EU AI Act `2024/1689@2026-07-27`; compliance/certification/supervisory conclusions remain prohibited.
- **v0.5 Portfolio & third-party model risk:** append-only provider profiles, exact model-version/provider dependencies, exit/test evidence, 10,000-bps portfolio snapshots and deterministic concentration/currentness assessments.
- **v0.4 AI/GenAI overlays:** exact foundation-model, prompt/system-policy, RAG, use-case, evaluation, human-oversight and revalidation evidence.
- **v0.3 Signed governance/change control:** Ed25519 verification-key evidence, signed governance envelopes, explicit materiality, signed change authorization and exact implementation evidence.
- **v0.2 Monitoring & drift:** exact-version monitoring plans, closed metric taxonomy, warning/breach thresholds and deterministic latest observations.
- **v0.1 Governance foundation:** immutable model/version inventory, SHA-256 provenance, deterministic risk tiering, independent validation, role-bound approval, bounded exceptions and revalidation evidence.

## CLI

After installation:

```bash
modelriskops contract-snapshot
modelriskops digest-json document.json
modelriskops validate-schema schema.json document.json
modelriskops verify-dossier governance-dossier.json
```

`contract-snapshot` and `verify-dossier` are local/non-executing governance utilities; neither invokes models or deployment infrastructure.

## Stable-release review handoff

An independent reviewer computes the candidate repository digest with:

```bash
python scripts/repository_review_digest.py
```

The reviewer then supplies a schema-valid `security-review/v1.0-review.json` with exact item outcomes, evidence/rationale digests, explicit independence and the computed repository digest. Generic PR, merge, project or release approval is not independent review and is not item-level residual-risk acceptance.

## Trust boundary and non-claims

ModelRiskOps binds governance artefacts to exact identities, versions and evidence digests. Missing, stale, expired or incomplete required inputs fail closed where the relevant contract requires them.

A valid signature does not by itself prove legal authority, trusted time or external-source authenticity. A healthy GenAI assessment does not establish model safety, factuality, fairness or privacy compliance. A healthy portfolio assessment does not establish vendor safety, solvency, outsourcing compliance or successful exit capability. An assurance mapping does not establish conformity or regulatory satisfaction. RLS/key artefacts do not prove live enforcement or hardware custody. `reference_ready` does not prove production deployment or fitness.

The v1 stable contract explicitly retains nine non-claims covering automated validation, certification/conformity, deployed RLS, hardware custody, legal/regulatory determinations, live deployment/model execution, model safety/factuality, production fitness and supervisory acceptance.

Institution-specific legal/privacy review, accountable model-risk ownership, production IAM/network controls, records retention, infrastructure testing, independent validation and supervisory engagement remain external responsibilities where applicable.

## Standards posture

Current design inputs/framework identities include:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management** (17 April 2026), superseding SR 11-7;
- NIST **AI Risk Management Framework 1.0**;
- NIST **AI 600-1 — Generative AI Profile**;
- ISO/IEC **42001:2023**; and
- Regulation (EU) **2024/1689**, represented against consolidated EUR-Lex revision `2024/1689@2026-07-27`.

These are architecture and assurance inputs, not legal-applicability, compliance, supervisory-approval, conformity or certification claims.

## Design principles

- Human accountability and applicability decisions remain explicit.
- Governance decisions bind exact model/version/evidence identities rather than mutable names.
- Historical evidence is immutable; current-use validation is separate and fail closed.
- Future evidence cannot satisfy an earlier represented governance or release time.
- Stable public contracts are narrow, machine-readable and SemVer-governed.
- Independent review is bound to exact repository content, not only a version label.
- Secret key material is not serialized by governance registries.
- Production-reference network/worker policies are default-deny, non-executing contracts rather than runtime-enforcement claims.
- Release readiness requires exact rollback, upgrade, recovery and provenance evidence.
- Regulatory mappings remain separate from legal conclusions and certification claims.
- The governance core does not train, deploy, call, probe, score or operate models, providers, networks, databases, KMS/HSM systems or deployment platforms.

## Roadmap

`v0.1 governance foundation → v0.2 monitoring & drift → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable governance reference`

Implementation of the v1 source contract does **not** imply that the formal `v1.0.0` tag has been released. The tag remains blocked until the independent-review contract is truthfully satisfied.

## License

Apache License 2.0.
