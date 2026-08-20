# ModelRiskOps v0.8 — Production Reference

## Purpose

v0.8 adds an offline production-reference control plane over the existing model-risk, assurance and tenant/cryptographic evidence layers. It determines whether a represented release has the exact current governance dependencies required by this reference architecture. It does not deploy software, invoke models, configure networks or operate cloud services.

## Runtime identity

`RuntimeIdentityProfile` binds one institution/tenant runtime identity to an exact v0.7 tenant-isolation profile, governed environment, workload identity, service account, issuer digest and audience digest. New profiles may bind only the current tenant-isolation evidence and cannot consume future isolation state.

Historical exact retries remain idempotent; `assert_identity_current()` is the explicit mutable currentness check.

## Default-deny HTTPS egress

`HttpsEgressPolicy` permits only exact, sorted DNS hostnames. The contract requires TLS, default deny, no wildcard hosts and no raw-IP destinations. It is evidence describing an intended network policy; ModelRiskOps does not configure firewalls, proxies, service meshes or cloud network policy.

## Isolated governance worker

`IsolatedWorkerProfile` binds the exact current runtime identity and egress policy. The reference requires a read-only root filesystem and no-new-privileges, and structurally disables shell access, subprocess execution, privileged containers and model invocation.

This is a deployment profile contract, not proof that a real container/runtime enforces the settings.

## Rollback, upgrade and recovery

A release is not reference-ready without all three:

- `RollbackPlan` — exact restore artifact, configuration restore, recovery procedure and rollback-validation evidence;
- `UpgradePlan` — exact source-release evidence, preflight, migration, post-upgrade validation and the exact registered rollback plan, with `backup_required=true`;
- `RecoveryCheckpoint` — exact current tenant-isolation snapshot, backup artifact and represented recovery-test evidence.

Readiness evidence cannot be created in the future relative to the represented release time.

## Deployment release manifest

`DeploymentReleaseManifest` binds:

- exact release ID/sequence/version and source Git commit SHA;
- package version and wheel SHA-256;
- SBOM, CI and provenance-attestation evidence digests;
- exact current tenant-isolation, runtime-identity, egress and isolated-worker digests;
- exact rollback, upgrade and recovery-checkpoint digests; and
- represented release time.

`release_version` must equal `package_version`. Production releases require production tenant/runtime profiles. Release sequences are append-only and contiguous.

The manifest structurally fixes `deployment_performed=false` and `model_invocation_performed=false`. It therefore cannot be used to claim that ModelRiskOps actually deployed or executed anything.

## Historical registration vs current eligibility

Immutable historical release registration remains idempotent after later drift. Current eligibility is separate:

- `assert_release_current()` revalidates the exact latest release and all mutable tenant/runtime/egress/worker dependencies;
- `assess_release()` returns only `reference_ready` or `ineligible` and never performs deployment.

If tenant isolation, runtime identity, egress or worker state drifts after a release is registered, the historical release remains reproducible while current eligibility fails closed.

## Explicit non-claims

v0.8 does not prove or perform:

- live deployment, rollout, rollback or recovery;
- Kubernetes/container-runtime enforcement;
- cloud IAM or workload-identity correctness;
- firewall, proxy, service-mesh or DNS enforcement;
- actual SBOM completeness or provenance-provider trustworthiness beyond represented digests;
- production database/RLS enforcement;
- KMS/HSM hardware custody or attestation;
- model execution, scoring, training or monitoring;
- production fitness, regulatory compliance, certification or supervisory acceptance.

The module remains an offline reference/evidence boundary. Institution-owned production engineering and security controls remain external responsibilities.
