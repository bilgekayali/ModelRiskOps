# Upgrading ModelRiskOps 0.8.x to 1.0.0

The declared v1 reference upgrade path is `0.8.x -> 1.0.0`.

## Exact evidence binding

`SupportedUpgradePath` binds the exact source and target `DeploymentReleaseManifest` digests. A matching version string alone is insufficient. The path also binds preflight, migration, post-upgrade-validation, and rollback evidence digests and requires backup evidence.

The v1 stable registry requires the source `0.8.x` release to remain present in the production-reference release history and requires the target `1.0.0` release to be the current production-reference release. This reflects the v0.8 registry's append-only history: once the v1 target is registered, the v0.8 predecessor is historical rather than current.

## Compatibility posture

The reference transition declares no intentional breaking migration of the v1 stable surface. The stable Python surface begins at `modelriskops.api`; earlier root-package imports remain available but are not themselves promoted to the stable contract.

Before an institutional upgrade, validate at minimum:

- exact source release identity and digest;
- backup/recovery evidence;
- tenant isolation and cryptographic-currentness evidence;
- runtime identity, egress, and isolated-worker currentness;
- package/wheel and provenance evidence;
- stable API/CLI/schema contract checks; and
- institution-specific deployment, IAM, network, records, legal/privacy, and model-risk procedures.

ModelRiskOps does not execute an upgrade, migrate a database, modify production IAM/networking, rotate institution keys, deploy a workload, or invoke a model. `SupportedUpgradePath` records reference evidence only.
