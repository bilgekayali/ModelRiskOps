# Security Policy

## Supported stable series

The declared stable compatibility series is ModelRiskOps `1.x`. Security fixes are prioritized over preserving behavior that would knowingly retain an unsafe control bypass; any compatibility impact must be documented explicitly.

## Reporting vulnerabilities

Please report security vulnerabilities privately through GitHub Security Advisories for this repository rather than opening a public issue containing exploit details, secrets, or sensitive institutional information.

Useful reports include the affected version/commit, impacted governance boundary, a minimal reproduction, expected versus observed behavior, and any evidence of privilege widening, fail-open behavior, cross-tenant substitution, signature/cryptographic misuse, stale-evidence acceptance, review/release bypass, or capability creep.

## High-priority security scope

High-priority findings include:

- model/version or evidence-digest substitution;
- validation, approval, exception, monitoring, change-control or revalidation bypass;
- signature verification, key-revocation or crypto-lifecycle bypass;
- cross-tenant or cross-institution evidence substitution;
- RLS/reference-isolation currentness bypass;
- provider/dependency/portfolio currentness or concentration manipulation;
- assurance mapping that can silently infer compliance/certification;
- production-reference egress or worker capability widening;
- release identity, chronology, rollback/upgrade/recovery or provenance bypass;
- stable API/schema contract bypass that could hide a breaking security change;
- independent-security-review or item-level risk-acceptance bypass; and
- introduction of model execution, deployment, network, database, secret-store, KMS/HSM or process-execution capability into an offline/reference-only core boundary.

## Stable release review

The formal `v1.0.0` tag is gated by `security-review/v1.0-review.json`. The review must be produced by a genuinely independent reviewer, cover the exact 12 required items, and bind the exact reviewed tracked-file state through `reviewed_repository_digest`.

Generic project, PR, merge or release approval is not independent-review evidence and is not item-level residual-risk acceptance. The implementation author must not fabricate reviewer independence, review closure, evidence, rationale or accountable-human risk acceptance.

## Security non-claims

ModelRiskOps is a governance-reference library. It does not itself prove production fitness, legal or regulatory compliance, supervisory acceptance, certification/conformity, deployed PostgreSQL RLS, KMS/HSM hardware custody, live network/IAM enforcement, model safety/factuality, or that any deployment/model invocation occurred.
