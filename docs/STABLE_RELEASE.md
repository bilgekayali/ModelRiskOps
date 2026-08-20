# ModelRiskOps v1 Stable Release

ModelRiskOps `1.0.0` establishes a stable governance-reference contract over the earlier v0.1-v0.8 control boundaries. It does not convert ModelRiskOps into a model runtime, deployment engine, regulator gateway, certification product, or production-fitness guarantee.

## Stable baseline composition

`StableReleaseBaseline` binds the exact digests of:

- the v1 compatibility policy;
- the stable public-surface manifest;
- the exact current `1.0.0` production-reference release manifest;
- the exact supported `0.8.x -> 1.0.0` upgrade path;
- the completed independent-security-review checklist;
- the responsibility/non-claim scope;
- the reproducible checksum manifest;
- the release provenance attestation; and
- evidence references for all eight governance boundaries.

The boundary set is inventory/risk, validation/approval, monitoring/change, GenAI, portfolio/third-party, assurance, tenant/crypto, and production reference.

Historical stable-baseline registration is immutable and idempotent. Current eligibility is a separate assertion: the exact target production-reference release must still be current and the exact source/target upgrade bindings must not have been substituted.

## Release chronology

The stable registry rejects readiness evidence that predates the artefact it purports to validate. In particular, the independent security review and responsibility scope cannot predate the exact `1.0.0` target release evidence, and the assembled stable baseline cannot predate any bound readiness artefact.

## Reproducibility and provenance

The release workflow builds the wheel twice with a commit-derived `SOURCE_DATE_EPOCH`, requires byte-identical SHA-256 results, emits `SHA256SUMS`, and performs GitHub artifact attestations on tagged releases.

For the `v1.0.0` tag, attestation is downstream of the independent-review gate. A tag cannot reach attestation merely because the package version matches.

## Independent-review blocker

The `v1.0.0` tag requires `security-review/v1.0-review.json`. The review must conform to the strict schema, cover all 12 required review items, explicitly confirm reviewer independence, and bind the exact reviewed repository state through `reviewed_repository_digest`.

The implementation author does not pre-populate this file. Project, merge, or release approval does not imply independent review or residual-risk acceptance.

## Non-claims

A stable ModelRiskOps release does not establish legal compliance, supervisory acceptance, certification, deployed RLS, hardware-backed key custody, model safety, factuality, live deployment, model execution, or production fitness. Those conclusions and operational controls remain with accountable institutions and qualified reviewers.
