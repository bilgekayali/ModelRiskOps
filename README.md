# ModelRiskOps

**Open model risk governance, validation, lifecycle controls and verifiable evidence for AI/ML systems in regulated environments.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, AI and generative-AI systems through a controlled lifecycle: inventory, risk classification, independent validation, approval, monitoring, signed change/revalidation evidence, AI/GenAI overlays, portfolio/third-party risk and framework assurance mappings.

Current package boundary: **ModelRiskOps v0.6.0 — Assurance Mappings**.

The project is designed for regulated and high-assurance environments. It is not a model-training framework, automated model validator, production monitoring platform, legal/compliance decision engine, certification product, regulator gateway or substitute for independent expert judgement.

## v0.6.0 assurance mappings

v0.6 extends the v0.5 governance evidence with a strict offline framework crosswalk:

- `AssuranceMappingProfile` defines an institution-owned, versioned required-reference catalog for one exact supported framework version and binds the source catalog/document digest;
- supported framework identities are Federal Reserve SR 26-2, NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001:2023 and the EU AI Act consolidated revision represented by this release as `2024/1689@2026-07-27`;
- `AssuranceScope` binds one exact governed subject/context to one current mapping profile per framework;
- `AssuranceApplicabilityAssertion` requires explicit human applicability decisions; applicable EU AI Act assertions additionally require at least one human-confirmed operator role;
- `AssuranceEvidenceReference` binds exact artifact digests, artifact type, source component and represented evidence basis;
- `AssuranceCrosswalkEntry` records only `supported`, `partial`, `gap` or `not_applicable`; supported/partial require exact evidence references and gap/not-applicable cannot carry them;
- mapping chronology rejects evidence registered after the represented mapping time;
- package construction is closed over the mapping profile: **every required reference** must have exactly one applicability assertion and one crosswalk entry, preventing favorable-reference cherry-picking;
- per-framework results are deterministic counts, not compliance scores or percentages;
- mapping-profile drift preserves historical package verification while `assert_package_current()` fails closed for current-use claims;
- the final package structurally fixes `certification_claimed=false`, `conformity_claimed=false`, `legal_compliance_determined=false`, `supervisory_acceptance_claimed=false`, and `requires_human_review=true`;
- six strict Draft 2020-12 schemas, adversarial tests, Python 3.11/3.12/3.13 clean-wheel CI and a dedicated Assurance Mappings Boundary cover the release.

Framework names, versions and reference catalogs are evidence/governance inputs. ModelRiskOps does not infer legal applicability, compliance, conformity, certification, supervisory sufficiency or regulator acceptance.

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

Private-key custody, KMS/HSM integration, trusted timestamping, external immutable anchoring, production IAM, tenant cryptographic isolation and third-party attestation remain later hardening milestones.

## Standards posture

Current design inputs/framework identities include:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management** (17 April 2026), which supersedes SR 11-7;
- NIST **AI Risk Management Framework 1.0** (NIST AI 100-1);
- NIST **AI 600-1 — Generative AI Profile**;
- ISO/IEC **42001:2023**; and
- Regulation (EU) **2024/1689** — EU Artificial Intelligence Act, with the current consolidated EUR-Lex revision represented by v0.6 as `2024/1689@2026-07-27`.

These are architecture and assurance inputs, not claims of legal applicability, compliance, supervisory approval, vendor safety, conformity or certification.

## Design principles

- Human accountability and applicability decisions remain explicit.
- Governance decisions bind to exact model/version and evidence digests rather than mutable names.
- Framework mapping profiles are institution-owned, versioned and source-digest bound.
- Assurance packaging is complete over the declared required-reference catalog; favorable-reference cherry-picking fails closed.
- Coverage labels are evidence classifications, not compliance conclusions.
- Historical evidence is preserved rather than silently overwritten; current-use validation is separate and fail closed.
- Future evidence cannot satisfy an earlier represented governance time.
- Regulatory mappings are separated from legal conclusions and certification claims.
- The governance core does not execute, train, deploy, call, probe or operate models, providers, regulators or standards services.

## Roadmap direction

`v0.1 governance foundation → v0.2 monitoring & drift evidence → v0.3 signed governance/change control → v0.4 AI/GenAI overlays → v0.5 portfolio & third-party model risk → v0.6 assurance mappings → v0.7 tenant/crypto hardening → v0.8 production reference → v1.0 stable release`

## License

Apache License 2.0.
