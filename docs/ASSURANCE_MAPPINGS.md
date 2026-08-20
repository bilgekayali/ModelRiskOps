# ModelRiskOps v0.6 — Assurance Mappings

## Purpose

ModelRiskOps v0.6 adds an offline assurance-evidence crosswalk over the existing model inventory, validation, monitoring, signed change-control, GenAI and portfolio/third-party evidence boundaries.

The boundary answers a deliberately narrow question:

> For an exact governed subject and an institution-owned reference catalog, which human-confirmed framework references are represented as supported, partial, gap or not applicable by exact evidence digests?

It does **not** answer whether a framework legally applies, whether a model or institution complies, whether certification/conformity has been achieved, or whether a supervisor will accept the evidence.

## Supported framework identities

The v0.6 runtime pins the framework identity/version strings that a mapping profile may represent:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management**: `SR 26-2`;
- NIST **AI Risk Management Framework 1.0**: `1.0`;
- NIST **AI 600-1 — Generative AI Profile**: `600-1`;
- ISO/IEC **42001:2023**: `2023`;
- EU AI Act **Regulation (EU) 2024/1689**, current consolidated revision represented by this release: `2024/1689@2026-07-27`.

A supported framework identity is only a version pin. ModelRiskOps does not ship a legal interpretation, licensed ISO text, regulator-approved control catalog or universal clause mapping.

## Institution-owned mapping profiles

`AssuranceMappingProfile` is append-only and versioned. It binds:

- one framework and exact supported framework version;
- an institution-owned, sorted set of required `reference_ids`;
- the SHA-256 digest of the source document/catalog used to define those references;
- an accountable owner; and
- registration time.

Profile versions are contiguous. New assurance scopes may bind only the current profile version. Historical exact retries remain idempotent, but they do not restore current eligibility after a profile update.

This design intentionally avoids embedding a claim that a hard-coded subset of clauses is universally applicable. The institution or qualified reviewer defines the references it intends to assess and owns that interpretation.

## Exact assurance scope

`AssuranceScope` binds one exact subject artifact and context digest to one current mapping profile per framework. Subject kinds include:

- model version;
- governance dossier;
- GenAI overlay;
- portfolio snapshot; and
- explicitly represented other artifacts.

Scope versions are append-only and contiguous. A profile revision makes an older scope historical rather than silently updating its crosswalk basis.

## Human-confirmed applicability

`AssuranceApplicabilityAssertion` records an explicit human decision for one exact scope/framework/reference tuple:

- `applicable`; or
- `not_applicable`.

The registry never infers applicability from model type, risk tier, geography, data category, deployment context or provider identity.

For EU AI Act mappings, an applicable assertion additionally requires at least one human-confirmed operator role such as `provider` or `deployer`. Those roles are represented governance inputs; ModelRiskOps does not determine the legal role automatically.

## Evidence references and crosswalk entries

`AssuranceEvidenceReference` binds an exact artifact digest, artifact type, source component and human-readable evidence basis to the scope.

`AssuranceCrosswalkEntry` then binds one exact applicability assertion to one of four coverage states:

- `supported` — requires at least one exact evidence reference;
- `partial` — requires at least one exact evidence reference;
- `gap` — carries no evidence reference;
- `not_applicable` — carries no evidence reference and is valid only when the exact human applicability assertion is `not_applicable`.

Mapping chronology is fail closed: a crosswalk cannot use evidence registered after its represented mapping time.

A `supported` mapping means only that the human mapper represented the cited evidence as support for the chosen reference. It does not mean the requirement is satisfied in law, that the evidence is authentic outside the represented digest boundary, or that the control is effective in production.

## Complete package closure

`AssuranceEvidenceRegistry.build_evidence_package()` does not accept a caller-selected subset of favorable mappings.

For every reference in every mapping profile bound to the exact scope, the registry requires:

1. exactly one applicability assertion; and
2. exactly one crosswalk entry.

If any required reference is omitted, package construction fails closed.

The package contains only evidence actually referenced by crosswalk entries and derives deterministic per-framework counts for `supported`, `partial`, `gap` and `not_applicable`. These are counts, not compliance scores or percentages.

## Historical verification versus current eligibility

Assurance artifacts are immutable historical evidence.

An already registered package can still be verified after a later mapping-profile revision because its historical digests remain valid. `assert_package_current()` is separate and fails when the exact scope or one of its mapping profiles is no longer current.

This separation preserves audit history without allowing stale framework/reference catalogs to masquerade as current assurance evidence.

## Structural non-claims

`AssuranceEvidencePackage` structurally enforces:

- `certification_claimed = false`;
- `conformity_claimed = false`;
- `legal_compliance_determined = false`;
- `supervisory_acceptance_claimed = false`; and
- `requires_human_review = true`.

These values are enforced in both the Python runtime and strict Draft 2020-12 JSON Schema.

## Primary design sources

The v0.6 framework identities are grounded in official sources:

- Federal Reserve SR 26-2, dated 17 April 2026, which supersedes SR 11-7;
- NIST AI RMF 1.0 (NIST AI 100-1);
- NIST AI 600-1 Generative AI Profile;
- ISO/IEC 42001:2023; and
- Regulation (EU) 2024/1689 as represented by the current consolidated EUR-Lex revision dated 27 July 2026.

These sources inform framework identity and architecture. They are not machine-executed legal rules.

## Explicit non-claims

ModelRiskOps v0.6 does not itself establish:

- legal or regulatory applicability;
- Federal Reserve/OCC/FDIC supervisory sufficiency under SR 26-2;
- NIST AI RMF implementation completeness;
- ISO/IEC 42001 conformity or certification;
- EU AI Act compliance, operator role, high-risk classification, conformity assessment or legal obligation satisfaction;
- evidence authenticity outside the exact represented digest boundary;
- control operating effectiveness;
- independent audit conclusions;
- regulator or supervisor acceptance;
- model safety, fairness, accuracy, resilience or production fitness.

The assurance core is an offline evidence-mapping and completeness boundary. It does not contact regulators, standards bodies, models, providers, production systems or external evidence stores.
