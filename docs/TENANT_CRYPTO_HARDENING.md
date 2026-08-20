# ModelRiskOps v0.7 — Tenant and Cryptographic Hardening

## Purpose

ModelRiskOps v0.7 adds an offline reference boundary for tenant isolation metadata, institution-owned KMS/HSM key references, key lifecycle, signed configuration-change evidence and tenant-bound encrypted governance evidence.

The boundary is deliberately narrower than a production security platform. It records and verifies exact governance artifacts; it does not connect to PostgreSQL, KMS, HSM, cloud IAM, secret stores or production workloads.

## PostgreSQL RLS reference

`PostgresRlsPolicy` represents a strict PostgreSQL row-level-security policy for one institution-scoped table. The renderer emits reference DDL with both `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`, and predicates bind exact institution and tenant session settings.

Identifiers and session-setting names are syntactically constrained before rendering. The renderer does not connect to PostgreSQL or prove that generated DDL has been deployed, enabled or tested in a real database.

## Tenant isolation profiles

`TenantIsolationProfile` binds:

- institution and tenant identity;
- governed environment;
- database role identity;
- a namespace/configuration digest; and
- exact current RLS policy digests.

RLS policies and tenant profiles are append-only and version-contiguous. New profiles may bind only current RLS policy versions and may not consume future policy evidence. Historical exact retries remain idempotent, while `assert_profile_current()` fails closed after policy or profile drift.

## Institution-owned cryptographic key references

`InstitutionCryptoKeyReference` stores metadata only:

- institution and tenant scope;
- purpose (`config_signing` or `evidence_encryption`);
- monotonically versioned key identity;
- represented custody (`kms` or `hsm`);
- governed algorithm;
- validity interval; and
- for Ed25519 signing only, the public verification key.

Private signing keys and AES key bytes are never stored by ModelRiskOps. AES-256-GCM references structurally reject embedded key material.

A KMS/HSM reference is represented governance evidence. It does not prove that a real hardware boundary exists, that a provider enforces custody correctly, or that production IAM permits only intended callers.

## Rotation, retirement and disablement

Key references are append-only and version-contiguous. Rotated versions must use distinct `key_id` values.

Lifecycle transitions are restricted to:

`active -> retired | disabled`

`retired -> disabled`

`disabled` is terminal.

For new cryptographic operations, ModelRiskOps selects the latest eligible key version only. It never falls back to an older active version after a newer version has been retired or disabled. This prevents version rollback.

Historical signatures remain verifiable against the key state at signing time. New operations require the current active key at the exact represented operation time.

## Signed configuration-change chain

`ConfigurationChangeRequest` records an institution/tenant-scoped configuration mutation with:

- monotonically increasing tenant sequence;
- object type and object identity;
- prior and proposed configuration digests;
- human requester identity;
- change-reason digest; and
- request/effective times.

`SignedConfigurationChange` binds the request to the exact configuration-signing key and previous tenant change digest. The core verifies Ed25519 signatures using the represented public key, but signing is performed by a caller-supplied signer whose key identity must exactly match the registered KMS/HSM reference.

`ConfigurationChangeRegistry` forms an append-only per-tenant chain. A change cannot become current before `effective_at`, cannot skip sequence numbers, cannot fork from the wrong previous change digest and cannot move backward in signing time.

The registry records configuration evidence only. It does not apply configuration to databases, IAM, KMS/HSM, deployment systems or model runtimes.

## Tenant-bound encrypted governance evidence

`EncryptedGovernanceEvidence` represents AES-256-GCM protected evidence produced by a caller-supplied encryptor. The core selects a fresh 96-bit nonce and constructs canonical AAD binding:

- envelope identity;
- institution identity;
- tenant identity;
- exact tenant-isolation-profile digest;
- exact encryption-key reference digest; and
- exact subject artifact digest.

The envelope records plaintext SHA-256, AAD SHA-256, nonce and ciphertext. It never records symmetric key bytes.

New encryption requires the exact current tenant-isolation profile and current active encryption key. Tenant/key substitutions fail closed through scope/currentness checks and AES-GCM authentication.

## Historical decryptability vs current eligibility

Isolation drift must not destroy audit history. Therefore historical encrypted evidence can still be decrypted against its exact registered historical isolation profile and key reference when that key is not disabled.

`assert_encrypted_evidence_current()` is a separate current-use check. It fails after isolation-profile/RLS drift or key disablement. This preserves immutable historical evidence without presenting stale isolation state as current.

## Explicit non-claims

ModelRiskOps v0.7 does not itself establish:

- deployed PostgreSQL RLS enforcement;
- tenant isolation in a live database, object store, queue, cache or runtime;
- KMS/HSM hardware custody, attestation or key non-exportability;
- production IAM correctness or least privilege;
- secret-store integration;
- cloud-provider security configuration;
- external key rotation actually occurring;
- successful production encryption at rest or in transit;
- regulatory compliance, certification, supervisory acceptance or production fitness.

The v0.7 module remains an offline evidence/control-plane reference. Production deployment, IAM, network isolation, release provenance, recovery and operational integration remain v0.8 work.
