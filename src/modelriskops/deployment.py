from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .canonical import sha256_digest
from .models import GovernanceError
from .hardening import TenantEnvironment, TenantIsolationRegistry

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _positive(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _timestamp(name: str, value: int) -> int:
    return _positive(name, value)


def _semver(name: str, value: str) -> str:
    value = _text(name, value)
    if not _SEMVER.fullmatch(value):
        raise GovernanceError(f"{name} must be semantic version text")
    return value


def _sorted_hosts(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise GovernanceError("allowed_https_hosts must not be empty")
    normalized: list[str] = []
    for value in values:
        host = _text("allowed_https_hosts", value).lower()
        if "*" in host or ":" in host or "/" in host or not _HOST.fullmatch(host):
            raise GovernanceError("allowed HTTPS egress hosts must be exact lowercase DNS names without wildcards, ports or paths")
        normalized.append(host)
    result = tuple(normalized)
    if len(result) != len(set(result)) or result != tuple(sorted(result)):
        raise GovernanceError("allowed_https_hosts must be unique and sorted")
    return result


class DeploymentState(str, Enum):
    REFERENCE_READY = "reference_ready"
    INELIGIBLE = "ineligible"


@dataclass(frozen=True, slots=True)
class RuntimeIdentityProfile:
    institution_id: str
    tenant_id: str
    profile_version: int
    environment: TenantEnvironment
    workload_identity: str
    service_account: str
    issuer_digest: str
    audience_digest: str
    tenant_isolation_profile_digest: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "workload_identity", "service_account"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("profile_version", self.profile_version)
        if not isinstance(self.environment, TenantEnvironment):
            raise GovernanceError("runtime identity environment must be governed")
        for name in ("issuer_digest", "audience_digest", "tenant_isolation_profile_digest"):
            _digest(name, getattr(self, name))
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class HttpsEgressPolicy:
    institution_id: str
    tenant_id: str
    policy_id: str
    policy_version: int
    allowed_https_hosts: tuple[str, ...]
    tls_required: bool
    default_deny: bool
    wildcard_hosts_allowed: bool
    raw_ip_egress_allowed: bool
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "policy_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("policy_version", self.policy_version)
        object.__setattr__(self, "allowed_https_hosts", _sorted_hosts(self.allowed_https_hosts))
        if self.tls_required is not True or self.default_deny is not True:
            raise GovernanceError("v0.8 production egress requires TLS and default deny")
        if self.wildcard_hosts_allowed is not False or self.raw_ip_egress_allowed is not False:
            raise GovernanceError("v0.8 production egress forbids wildcard hosts and raw IP destinations")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IsolatedWorkerProfile:
    institution_id: str
    tenant_id: str
    worker_id: str
    profile_version: int
    runtime_identity_profile_digest: str
    egress_policy_digest: str
    read_only_root_filesystem: bool
    no_new_privileges: bool
    shell_access_enabled: bool
    subprocess_execution_enabled: bool
    privileged_container: bool
    model_invocation_enabled: bool
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "worker_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("profile_version", self.profile_version)
        _digest("runtime_identity_profile_digest", self.runtime_identity_profile_digest)
        _digest("egress_policy_digest", self.egress_policy_digest)
        if self.read_only_root_filesystem is not True or self.no_new_privileges is not True:
            raise GovernanceError("v0.8 isolated worker requires read-only root filesystem and no-new-privileges")
        if self.shell_access_enabled is not False or self.subprocess_execution_enabled is not False or self.privileged_container is not False:
            raise GovernanceError("v0.8 isolated worker forbids shell, subprocess and privileged-container capabilities")
        if self.model_invocation_enabled is not False:
            raise GovernanceError("ModelRiskOps production reference must not invoke models")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    institution_id: str
    tenant_id: str
    release_id: str
    release_version: str
    restore_artifact_digest: str
    configuration_restore_digest: str
    data_recovery_procedure_digest: str
    rollback_validation_digest: str
    declared_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "release_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "release_version", _semver("release_version", self.release_version))
        for name in ("restore_artifact_digest", "configuration_restore_digest", "data_recovery_procedure_digest", "rollback_validation_digest"):
            _digest(name, getattr(self, name))
        _timestamp("declared_at", self.declared_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class UpgradePlan:
    institution_id: str
    tenant_id: str
    release_id: str
    release_version: str
    source_release_digest: str
    preflight_evidence_digest: str
    migration_evidence_digest: str
    post_upgrade_validation_digest: str
    rollback_plan_digest: str
    backup_required: bool
    declared_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "release_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "release_version", _semver("release_version", self.release_version))
        for name in (
            "source_release_digest", "preflight_evidence_digest", "migration_evidence_digest",
            "post_upgrade_validation_digest", "rollback_plan_digest",
        ):
            _digest(name, getattr(self, name))
        if self.backup_required is not True:
            raise GovernanceError("v0.8 production upgrades require a backup")
        _timestamp("declared_at", self.declared_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RecoveryCheckpoint:
    institution_id: str
    tenant_id: str
    checkpoint_id: str
    release_id: str
    release_version: str
    tenant_isolation_snapshot_digest: str
    backup_artifact_digest: str
    recovery_test_evidence_digest: str
    captured_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "checkpoint_id", "release_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "release_version", _semver("release_version", self.release_version))
        for name in ("tenant_isolation_snapshot_digest", "backup_artifact_digest", "recovery_test_evidence_digest"):
            _digest(name, getattr(self, name))
        _timestamp("captured_at", self.captured_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DeploymentReleaseManifest:
    institution_id: str
    tenant_id: str
    release_id: str
    release_sequence: int
    release_version: str
    source_commit_sha: str
    package_version: str
    wheel_sha256: str
    sbom_digest: str
    ci_evidence_digest: str
    provenance_attestation_digest: str
    tenant_isolation_profile_digest: str
    runtime_identity_profile_digest: str
    egress_policy_digest: str
    worker_profile_digest: str
    rollback_plan_digest: str
    upgrade_plan_digest: str
    recovery_checkpoint_digest: str
    released_at: int
    deployment_performed: bool = False
    model_invocation_performed: bool = False

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "release_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("release_sequence", self.release_sequence)
        object.__setattr__(self, "release_version", _semver("release_version", self.release_version))
        object.__setattr__(self, "package_version", _semver("package_version", self.package_version))
        if self.release_version != self.package_version:
            raise GovernanceError("production reference release_version must equal package_version")
        if not isinstance(self.source_commit_sha, str) or not _GIT_SHA40.fullmatch(self.source_commit_sha):
            raise GovernanceError("source_commit_sha must be an exact lowercase 40-character Git commit SHA")
        for name in (
            "wheel_sha256", "sbom_digest", "ci_evidence_digest", "provenance_attestation_digest",
            "tenant_isolation_profile_digest", "runtime_identity_profile_digest", "egress_policy_digest",
            "worker_profile_digest", "rollback_plan_digest", "upgrade_plan_digest", "recovery_checkpoint_digest",
        ):
            _digest(name, getattr(self, name))
        _timestamp("released_at", self.released_at)
        if self.deployment_performed is not False or self.model_invocation_performed is not False:
            raise GovernanceError("ModelRiskOps release manifests are reference evidence and cannot claim deployment or model invocation")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DeploymentEligibilityAssessment:
    institution_id: str
    tenant_id: str
    release_manifest_digest: str
    state: DeploymentState
    assessed_at: int
    deployment_performed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "institution_id", _text("institution_id", self.institution_id))
        object.__setattr__(self, "tenant_id", _text("tenant_id", self.tenant_id))
        _digest("release_manifest_digest", self.release_manifest_digest)
        if not isinstance(self.state, DeploymentState):
            raise GovernanceError("deployment assessment state must be governed")
        _timestamp("assessed_at", self.assessed_at)
        if self.deployment_performed is not False:
            raise GovernanceError("deployment eligibility assessment must not claim deployment execution")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class ProductionDeploymentRegistry:
    """Offline production-reference control plane. It validates deployment evidence but deploys nothing."""

    def __init__(self, *, tenant_isolation_registry: TenantIsolationRegistry) -> None:
        if not isinstance(tenant_isolation_registry, TenantIsolationRegistry):
            raise GovernanceError("production deployment registry requires the v0.7 tenant isolation registry")
        self.tenant_isolation_registry = tenant_isolation_registry
        self._identities: dict[tuple[str, str, int], RuntimeIdentityProfile] = {}
        self._egress: dict[tuple[str, str, str, int], HttpsEgressPolicy] = {}
        self._workers: dict[tuple[str, str, str, int], IsolatedWorkerProfile] = {}
        self._rollbacks: dict[tuple[str, str, str, str], RollbackPlan] = {}
        self._upgrades: dict[tuple[str, str, str, str], UpgradePlan] = {}
        self._checkpoints: dict[tuple[str, str, str], RecoveryCheckpoint] = {}
        self._releases: dict[tuple[str, str, int], DeploymentReleaseManifest] = {}

    @staticmethod
    def _contiguous(history: tuple[object, ...], version: int, *, label: str, attr: str) -> None:
        expected = 1 if not history else getattr(history[-1], attr) + 1
        if version != expected:
            raise GovernanceError(f"{label} versions must be contiguous; expected version {expected}")

    def _egress_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> HttpsEgressPolicy:
        for item in self._egress.values():
            if item.institution_id == institution_id and item.tenant_id == tenant_id and item.evidence_digest == digest:
                return item
        raise GovernanceError("unknown tenant egress policy digest")

    def _worker_by_digest(self, institution_id: str, tenant_id: str, digest: str) -> IsolatedWorkerProfile:
        for item in self._workers.values():
            if item.institution_id == institution_id and item.tenant_id == tenant_id and item.evidence_digest == digest:
                return item
        raise GovernanceError("unknown tenant worker profile digest")

    def identity_history(self, institution_id: str, tenant_id: str) -> tuple[RuntimeIdentityProfile, ...]:
        return tuple(sorted((item for (scope, tenant, _), item in self._identities.items() if scope == institution_id and tenant == tenant_id), key=lambda item: item.profile_version))

    def register_identity(self, profile: RuntimeIdentityProfile) -> str:
        identity = (profile.institution_id, profile.tenant_id, profile.profile_version)
        existing = self._identities.get(identity)
        if existing is not None:
            if existing.evidence_digest != profile.evidence_digest:
                raise GovernanceError("runtime identity profile version already exists with different content")
            return existing.evidence_digest
        isolation = self.tenant_isolation_registry.profile_by_digest(profile.institution_id, profile.tenant_id, profile.tenant_isolation_profile_digest)
        self.tenant_isolation_registry.assert_profile_current(isolation)
        if isolation.environment is not profile.environment:
            raise GovernanceError("runtime identity environment must match exact tenant isolation profile")
        if isolation.registered_at > profile.registered_at:
            raise GovernanceError("runtime identity cannot bind future tenant isolation evidence")
        history = self.identity_history(profile.institution_id, profile.tenant_id)
        self._contiguous(history, profile.profile_version, label="runtime identity profile", attr="profile_version")
        if history and profile.registered_at < history[-1].registered_at:
            raise GovernanceError("runtime identity profile cannot move backward in time")
        self._identities[identity] = profile
        return profile.evidence_digest

    def current_identity(self, institution_id: str, tenant_id: str) -> RuntimeIdentityProfile:
        history = self.identity_history(institution_id, tenant_id)
        if not history:
            raise GovernanceError("runtime identity profile is not registered")
        return history[-1]

    def assert_identity_current(self, profile: RuntimeIdentityProfile) -> None:
        if self.current_identity(profile.institution_id, profile.tenant_id).evidence_digest != profile.evidence_digest:
            raise GovernanceError("runtime identity profile is stale")
        isolation = self.tenant_isolation_registry.profile_by_digest(profile.institution_id, profile.tenant_id, profile.tenant_isolation_profile_digest)
        self.tenant_isolation_registry.assert_profile_current(isolation)

    def egress_history(self, institution_id: str, tenant_id: str, policy_id: str) -> tuple[HttpsEgressPolicy, ...]:
        return tuple(sorted((item for (scope, tenant, candidate, _), item in self._egress.items() if scope == institution_id and tenant == tenant_id and candidate == policy_id), key=lambda item: item.policy_version))

    def register_egress(self, policy: HttpsEgressPolicy) -> str:
        identity = (policy.institution_id, policy.tenant_id, policy.policy_id, policy.policy_version)
        existing = self._egress.get(identity)
        if existing is not None:
            if existing.evidence_digest != policy.evidence_digest:
                raise GovernanceError("egress policy version already exists with different content")
            return existing.evidence_digest
        history = self.egress_history(policy.institution_id, policy.tenant_id, policy.policy_id)
        self._contiguous(history, policy.policy_version, label="egress policy", attr="policy_version")
        if history and policy.registered_at < history[-1].registered_at:
            raise GovernanceError("egress policy cannot move backward in time")
        self._egress[identity] = policy
        return policy.evidence_digest

    def current_egress(self, institution_id: str, tenant_id: str, policy_id: str) -> HttpsEgressPolicy:
        history = self.egress_history(institution_id, tenant_id, policy_id)
        if not history:
            raise GovernanceError("egress policy is not registered")
        return history[-1]

    def assert_egress_current(self, policy: HttpsEgressPolicy) -> None:
        if self.current_egress(policy.institution_id, policy.tenant_id, policy.policy_id).evidence_digest != policy.evidence_digest:
            raise GovernanceError("egress policy is stale")

    def worker_history(self, institution_id: str, tenant_id: str, worker_id: str) -> tuple[IsolatedWorkerProfile, ...]:
        return tuple(sorted((item for (scope, tenant, candidate, _), item in self._workers.items() if scope == institution_id and tenant == tenant_id and candidate == worker_id), key=lambda item: item.profile_version))

    def register_worker(self, profile: IsolatedWorkerProfile) -> str:
        identity = (profile.institution_id, profile.tenant_id, profile.worker_id, profile.profile_version)
        existing = self._workers.get(identity)
        if existing is not None:
            if existing.evidence_digest != profile.evidence_digest:
                raise GovernanceError("worker profile version already exists with different content")
            return existing.evidence_digest
        identity_profile = self.current_identity(profile.institution_id, profile.tenant_id)
        if identity_profile.evidence_digest != profile.runtime_identity_profile_digest:
            raise GovernanceError("worker must bind the exact current runtime identity profile")
        egress = self._egress_by_digest(profile.institution_id, profile.tenant_id, profile.egress_policy_digest)
        self.assert_egress_current(egress)
        if identity_profile.registered_at > profile.registered_at or egress.registered_at > profile.registered_at:
            raise GovernanceError("worker cannot bind future runtime or egress evidence")
        history = self.worker_history(profile.institution_id, profile.tenant_id, profile.worker_id)
        self._contiguous(history, profile.profile_version, label="worker profile", attr="profile_version")
        if history and profile.registered_at < history[-1].registered_at:
            raise GovernanceError("worker profile cannot move backward in time")
        self._workers[identity] = profile
        return profile.evidence_digest

    def current_worker(self, institution_id: str, tenant_id: str, worker_id: str) -> IsolatedWorkerProfile:
        history = self.worker_history(institution_id, tenant_id, worker_id)
        if not history:
            raise GovernanceError("worker profile is not registered")
        return history[-1]

    def assert_worker_current(self, profile: IsolatedWorkerProfile) -> None:
        if self.current_worker(profile.institution_id, profile.tenant_id, profile.worker_id).evidence_digest != profile.evidence_digest:
            raise GovernanceError("worker profile is stale")
        identity = self.current_identity(profile.institution_id, profile.tenant_id)
        if identity.evidence_digest != profile.runtime_identity_profile_digest:
            raise GovernanceError("worker runtime identity binding is stale")
        egress = self._egress_by_digest(profile.institution_id, profile.tenant_id, profile.egress_policy_digest)
        self.assert_egress_current(egress)
        self.assert_identity_current(identity)

    def register_rollback(self, plan: RollbackPlan) -> str:
        identity = (plan.institution_id, plan.tenant_id, plan.release_id, plan.release_version)
        existing = self._rollbacks.get(identity)
        if existing is not None and existing.evidence_digest != plan.evidence_digest:
            raise GovernanceError("rollback plan already exists with different content")
        self._rollbacks.setdefault(identity, plan)
        return plan.evidence_digest

    def register_upgrade(self, plan: UpgradePlan) -> str:
        identity = (plan.institution_id, plan.tenant_id, plan.release_id, plan.release_version)
        existing = self._upgrades.get(identity)
        if existing is not None:
            if existing.evidence_digest != plan.evidence_digest:
                raise GovernanceError("upgrade plan already exists with different content")
            return existing.evidence_digest
        rollback = self._rollbacks.get(identity)
        if rollback is None or rollback.evidence_digest != plan.rollback_plan_digest:
            raise GovernanceError("upgrade plan requires the exact registered rollback plan")
        if rollback.declared_at > plan.declared_at:
            raise GovernanceError("upgrade plan cannot bind future rollback evidence")
        self._upgrades[identity] = plan
        return plan.evidence_digest

    def register_checkpoint(self, checkpoint: RecoveryCheckpoint) -> str:
        identity = (checkpoint.institution_id, checkpoint.tenant_id, checkpoint.checkpoint_id)
        existing = self._checkpoints.get(identity)
        if existing is not None:
            if existing.evidence_digest != checkpoint.evidence_digest:
                raise GovernanceError("recovery checkpoint already exists with different content")
            return existing.evidence_digest
        current_snapshot = self.tenant_isolation_registry.snapshot_digest(checkpoint.institution_id, checkpoint.tenant_id)
        if current_snapshot != checkpoint.tenant_isolation_snapshot_digest:
            raise GovernanceError("recovery checkpoint tenant isolation snapshot is stale")
        self._checkpoints[identity] = checkpoint
        return checkpoint.evidence_digest

    def release_history(self, institution_id: str, tenant_id: str) -> tuple[DeploymentReleaseManifest, ...]:
        return tuple(sorted((item for (scope, tenant, _), item in self._releases.items() if scope == institution_id and tenant == tenant_id), key=lambda item: item.release_sequence))

    def register_release(self, manifest: DeploymentReleaseManifest) -> str:
        identity = (manifest.institution_id, manifest.tenant_id, manifest.release_sequence)
        existing = self._releases.get(identity)
        if existing is not None:
            if existing.evidence_digest != manifest.evidence_digest:
                raise GovernanceError("release sequence already exists with different content")
            return existing.evidence_digest
        identity_profile = self.current_identity(manifest.institution_id, manifest.tenant_id)
        if identity_profile.evidence_digest != manifest.runtime_identity_profile_digest:
            raise GovernanceError("release runtime identity profile is stale")
        isolation = self.tenant_isolation_registry.profile_by_digest(manifest.institution_id, manifest.tenant_id, manifest.tenant_isolation_profile_digest)
        self.tenant_isolation_registry.assert_profile_current(isolation)
        if isolation.environment is not TenantEnvironment.PRODUCTION:
            raise GovernanceError("v0.8 production release requires a production tenant isolation profile")
        if identity_profile.environment is not TenantEnvironment.PRODUCTION:
            raise GovernanceError("v0.8 production release requires a production runtime identity")
        if identity_profile.tenant_isolation_profile_digest != isolation.evidence_digest:
            raise GovernanceError("release identity does not bind exact tenant isolation profile")
        egress = self._egress_by_digest(manifest.institution_id, manifest.tenant_id, manifest.egress_policy_digest)
        self.assert_egress_current(egress)
        worker = self._worker_by_digest(manifest.institution_id, manifest.tenant_id, manifest.worker_profile_digest)
        self.assert_worker_current(worker)
        artifact_identity = (manifest.institution_id, manifest.tenant_id, manifest.release_id, manifest.release_version)
        rollback = self._rollbacks.get(artifact_identity)
        if rollback is None or rollback.evidence_digest != manifest.rollback_plan_digest:
            raise GovernanceError("release requires the exact registered rollback plan")
        upgrade = self._upgrades.get(artifact_identity)
        if upgrade is None or upgrade.evidence_digest != manifest.upgrade_plan_digest:
            raise GovernanceError("release requires the exact registered upgrade plan")
        if upgrade.rollback_plan_digest != rollback.evidence_digest:
            raise GovernanceError("release upgrade plan does not bind the exact rollback plan")
        checkpoint = next((item for item in self._checkpoints.values() if item.institution_id == manifest.institution_id and item.tenant_id == manifest.tenant_id and item.evidence_digest == manifest.recovery_checkpoint_digest), None)
        if checkpoint is None:
            raise GovernanceError("release requires the exact registered recovery checkpoint")
        if checkpoint.release_id != manifest.release_id or checkpoint.release_version != manifest.release_version:
            raise GovernanceError("recovery checkpoint must target the exact release identity")
        for evidence_time in (identity_profile.registered_at, egress.registered_at, worker.registered_at, rollback.declared_at, upgrade.declared_at, checkpoint.captured_at):
            if evidence_time > manifest.released_at:
                raise GovernanceError("production release cannot bind future readiness evidence")
        history = self.release_history(manifest.institution_id, manifest.tenant_id)
        expected = 1 if not history else history[-1].release_sequence + 1
        if manifest.release_sequence != expected:
            raise GovernanceError(f"production release sequence must be contiguous; expected {expected}")
        if history and manifest.released_at < history[-1].released_at:
            raise GovernanceError("production release history cannot move backward in time")
        self._releases[identity] = manifest
        return manifest.evidence_digest

    def assert_release_current(self, manifest: DeploymentReleaseManifest) -> None:
        history = self.release_history(manifest.institution_id, manifest.tenant_id)
        if not history or history[-1].evidence_digest != manifest.evidence_digest:
            raise GovernanceError("production release manifest is stale")
        identity = self.current_identity(manifest.institution_id, manifest.tenant_id)
        if identity.evidence_digest != manifest.runtime_identity_profile_digest:
            raise GovernanceError("release runtime identity profile is stale")
        self.assert_identity_current(identity)
        egress = self._egress_by_digest(manifest.institution_id, manifest.tenant_id, manifest.egress_policy_digest)
        self.assert_egress_current(egress)
        worker = self._worker_by_digest(manifest.institution_id, manifest.tenant_id, manifest.worker_profile_digest)
        self.assert_worker_current(worker)
        isolation = self.tenant_isolation_registry.profile_by_digest(manifest.institution_id, manifest.tenant_id, manifest.tenant_isolation_profile_digest)
        self.tenant_isolation_registry.assert_profile_current(isolation)

    def assess_release(self, manifest: DeploymentReleaseManifest, *, assessed_at: int) -> DeploymentEligibilityAssessment:
        _timestamp("assessed_at", assessed_at)
        if assessed_at < manifest.released_at:
            raise GovernanceError("deployment eligibility cannot predate release evidence")
        try:
            self.assert_release_current(manifest)
            state = DeploymentState.REFERENCE_READY
        except GovernanceError:
            state = DeploymentState.INELIGIBLE
        return DeploymentEligibilityAssessment(
            institution_id=manifest.institution_id,
            tenant_id=manifest.tenant_id,
            release_manifest_digest=manifest.evidence_digest,
            state=state,
            assessed_at=assessed_at,
        )
