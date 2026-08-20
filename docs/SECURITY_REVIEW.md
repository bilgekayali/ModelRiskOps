# ModelRiskOps v1 Security Review Contract

The `v1.0.0` stable tag requires a completed `IndependentSecurityReviewChecklist`. This is a release-governance control, not a declaration that ModelRiskOps is certified, regulator-approved, or production-safe for every institution.

## Closure semantics

All 12 required items must be present in canonical order. There is no `open`, `unknown`, pass-by-default, empty, or inferred status.

Each item is either:

- `closed`, with an exact evidence digest and reviewer-rationale digest; or
- `risk_accepted`, with those review digests plus an accountable-human identifier and an exact risk-acceptance evidence digest.

Risk acceptance is specific to the affected review item. A generic approval to merge, release, publish, or proceed must not be silently reinterpreted as item-level risk acceptance.

## Reviewer independence

`reviewer_independence_confirmed=true` is an explicit assertion made by the party producing the review artefact. The repository does not infer independence from a username, organization, job title, approval state, or absence of code changes.

The implementation author must not fabricate this field or represent synthetic test data as an independent review.

## Exact repository-state binding

The review contains `reviewed_repository_digest`, produced by `python scripts/repository_review_digest.py`. The digest covers all Git-tracked paths and bytes except the final `security-review/v1.0-review.json` file itself.

At `v1.0.0` tag time, the release workflow recomputes this digest and requires an exact match. Any other tracked-file change after review invalidates the review for that tag state.

## Review scope

The required items cover approval/exceptions/revalidation; assurance non-claims; GenAI/human oversight; independent validation/findings; inventory/provenance; monitoring/change control; portfolio/third-party risk; production-reference egress/worker isolation; release provenance/upgrade; risk-policy determinism; signing/key revocation; and tenant-isolation/crypto lifecycle.

A completed review remains evidence about the reviewed repository state. It does not substitute for institution-specific model validation, legal/privacy analysis, infrastructure testing, penetration testing, IAM/network review, vendor due diligence, business continuity testing, or supervisory engagement where those are required.
