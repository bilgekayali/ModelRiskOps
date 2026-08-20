# ModelRiskOps v1.0 Independent Security Review

The stable `v1.0.0` tag is intentionally fail-closed until a genuine independent security review is supplied as:

`security-review/v1.0-review.json`

The completed file is intentionally **not** pre-populated by the implementation author or by automation.

## Reviewer requirements

The reviewer must independently assess the exact repository state represented by `reviewed_repository_digest`, explicitly confirm reviewer independence, and resolve all 12 canonical review items defined by `IndependentSecurityReviewChecklist`.

Each item must be either:

- `closed`: the reviewer considers the represented finding/control satisfactorily resolved and supplies evidence and rationale digests; or
- `risk_accepted`: a residual risk remains and an accountable human has explicitly accepted that specific residual risk, with both `risk_acceptance_human_id` and `risk_acceptance_digest` supplied.

A generic project approval, pull-request approval, merge approval, release authorization, or statement such as "I accept the release" is **not** item-level residual-risk acceptance.

The implementation author must not fabricate reviewer identity, reviewer independence, review outcomes, evidence, rationale, or risk acceptance on behalf of another party.

## Exact reviewed repository binding

Compute the candidate source digest with:

```bash
python scripts/repository_review_digest.py
```

Record the resulting lowercase SHA-256 value in `reviewed_repository_digest`.

The digest covers every Git-tracked file path and its bytes except `security-review/v1.0-review.json`. Excluding only the final review artifact permits that artifact to be committed after review without changing the reviewed source digest. Any other tracked-file change after review changes the digest and causes the `v1.0.0` tag gate to fail until the changed repository state is reviewed again.

## Required review items

The exact ordered item set is:

1. `approval-exception-and-revalidation`
2. `assurance-non-claims`
3. `genai-overlay-and-human-oversight`
4. `independent-validation-and-findings`
5. `inventory-version-and-provenance`
6. `monitoring-and-change-control`
7. `portfolio-and-third-party-risk`
8. `production-reference-egress-and-worker`
9. `release-provenance-and-upgrade`
10. `risk-policy-determinism`
11. `signing-and-key-revocation`
12. `tenant-isolation-and-crypto-lifecycle`

The file must conform to `schemas/independent-security-review-checklist.schema.json`.

Do not copy a synthetic test fixture or example and present it as an independent review. Tests demonstrate contract behavior; they are not independent security-review evidence.
