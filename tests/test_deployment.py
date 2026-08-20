from dataclasses import replace

import pytest

from modelriskops.models import GovernanceError
from modelriskops.hardening import (
    PostgresRlsPolicy,
    TenantEnvironment,
    TenantIsolationProfile,
    TenantIsolationRegistry,
)
from modelriskops.deployment import (
    DeploymentReleaseManifest,
    DeploymentState,
    HttpsEgressPolicy,
    IsolatedWorkerProfile,
    ProductionDeploymentRegistry,
    RecoveryCheckpoint,
    RollbackPlan,
    RuntimeIdentityProfile,
    UpgradePlan,
)

D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64
D7 = "7" * 64
D8 = "8" * 64
D9 = "9" * 64


class Fixture:
    def __init__(self) -> None:
        self.isolation = TenantIsolationRegistry()
        self.rls = PostgresRlsPolicy(
            institution_id="bank-demo",
            policy_id="governance-evidence",
            policy_version=1,
            table_name="governance_evidence",
            policy_name="tenant_guard",
            institution_column="institution_id",
            tenant_column="tenant_id",
            institution_setting="modelriskops.institution_id",
            tenant_setting="modelriskops.tenant_id",
            force_row_level_security=True,
            registered_at=100,
        )
        self.isolation.register_policy(self.rls)
        self.tenant = TenantIsolationProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=TenantEnvironment.PRODUCTION,
            database_role="tenant_a_runtime",
            namespace_digest=D1,
            rls_policy_digests=(self.rls.evidence_digest,),
            registered_at=110,
        )
        self.isolation.register_profile(self.tenant)
        self.registry = ProductionDeploymentRegistry(tenant_isolation_registry=self.isolation)
        self.identity = RuntimeIdentityProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=TenantEnvironment.PRODUCTION,
            workload_identity="modelriskops-prod",
            service_account="modelriskops-prod-sa",
            issuer_digest=D2,
            audience_digest=D3,
            tenant_isolation_profile_digest=self.tenant.evidence_digest,
            registered_at=120,
        )
        self.registry.register_identity(self.identity)
        self.egress = HttpsEgressPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_id="governance-egress",
            policy_version=1,
            allowed_https_hosts=("evidence.example.com", "telemetry.example.com"),
            tls_required=True,
            default_deny=True,
            wildcard_hosts_allowed=False,
            raw_ip_egress_allowed=False,
            registered_at=130,
        )
        self.registry.register_egress(self.egress)
        self.worker = IsolatedWorkerProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            worker_id="governance-worker",
            profile_version=1,
            runtime_identity_profile_digest=self.identity.evidence_digest,
            egress_policy_digest=self.egress.evidence_digest,
            read_only_root_filesystem=True,
            no_new_privileges=True,
            shell_access_enabled=False,
            subprocess_execution_enabled=False,
            privileged_container=False,
            model_invocation_enabled=False,
            registered_at=140,
        )
        self.registry.register_worker(self.worker)
        self.rollback = RollbackPlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            release_id="modelriskops-v0.8",
            release_version="0.8.0",
            restore_artifact_digest=D4,
            configuration_restore_digest=D5,
            data_recovery_procedure_digest=D6,
            rollback_validation_digest=D7,
            declared_at=150,
        )
        self.registry.register_rollback(self.rollback)
        self.upgrade = UpgradePlan(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            release_id="modelriskops-v0.8",
            release_version="0.8.0",
            source_release_digest=D8,
            preflight_evidence_digest=D1,
            migration_evidence_digest=D2,
            post_upgrade_validation_digest=D3,
            rollback_plan_digest=self.rollback.evidence_digest,
            backup_required=True,
            declared_at=160,
        )
        self.registry.register_upgrade(self.upgrade)
        self.checkpoint = RecoveryCheckpoint(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            checkpoint_id="pre-v0.8",
            release_id="modelriskops-v0.8",
            release_version="0.8.0",
            tenant_isolation_snapshot_digest=self.isolation.snapshot_digest("bank-demo", "tenant-a"),
            backup_artifact_digest=D4,
            recovery_test_evidence_digest=D5,
            captured_at=170,
        )
        self.registry.register_checkpoint(self.checkpoint)
        self.release = DeploymentReleaseManifest(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            release_id="modelriskops-v0.8",
            release_sequence=1,
            release_version="0.8.0",
            source_commit_sha="a" * 40,
            package_version="0.8.0",
            wheel_sha256=D6,
            sbom_digest=D7,
            ci_evidence_digest=D8,
            provenance_attestation_digest=D9,
            tenant_isolation_profile_digest=self.tenant.evidence_digest,
            runtime_identity_profile_digest=self.identity.evidence_digest,
            egress_policy_digest=self.egress.evidence_digest,
            worker_profile_digest=self.worker.evidence_digest,
            rollback_plan_digest=self.rollback.evidence_digest,
            upgrade_plan_digest=self.upgrade.evidence_digest,
            recovery_checkpoint_digest=self.checkpoint.evidence_digest,
            released_at=180,
        )


def test_complete_production_reference_is_reference_ready_without_deploying() -> None:
    fx = Fixture()
    fx.registry.register_release(fx.release)
    assessment = fx.registry.assess_release(fx.release, assessed_at=190)
    assert assessment.state is DeploymentState.REFERENCE_READY
    assert assessment.deployment_performed is False
    assert fx.release.deployment_performed is False
    assert fx.release.model_invocation_performed is False


def test_egress_is_exact_default_deny_https_only() -> None:
    with pytest.raises(GovernanceError, match="exact lowercase DNS"):
        HttpsEgressPolicy(
            institution_id="bank-demo", tenant_id="tenant-a", policy_id="bad", policy_version=1,
            allowed_https_hosts=("*.example.com",), tls_required=True, default_deny=True,
            wildcard_hosts_allowed=False, raw_ip_egress_allowed=False, registered_at=1,
        )
    with pytest.raises(GovernanceError, match="TLS and default deny"):
        HttpsEgressPolicy(
            institution_id="bank-demo", tenant_id="tenant-a", policy_id="bad", policy_version=1,
            allowed_https_hosts=("api.example.com",), tls_required=True, default_deny=False,
            wildcard_hosts_allowed=False, raw_ip_egress_allowed=False, registered_at=1,
        )


def test_worker_cannot_gain_execution_capabilities() -> None:
    fx = Fixture()
    with pytest.raises(GovernanceError, match="must not invoke models"):
        replace(fx.worker, model_invocation_enabled=True)
    with pytest.raises(GovernanceError, match="forbids shell"):
        replace(fx.worker, shell_access_enabled=True)


def test_upgrade_requires_exact_registered_rollback_plan() -> None:
    fx = Fixture()
    bad = replace(fx.upgrade, release_id="other-release", rollback_plan_digest=D9)
    with pytest.raises(GovernanceError, match="exact registered rollback"):
        fx.registry.register_upgrade(bad)


def test_release_rejects_future_readiness_evidence() -> None:
    fx = Fixture()
    late = replace(fx.release, released_at=165)
    with pytest.raises(GovernanceError, match="future readiness evidence"):
        fx.registry.register_release(late)


def test_historical_release_retry_survives_drift_but_currentness_fails_closed() -> None:
    fx = Fixture()
    digest = fx.registry.register_release(fx.release)
    egress_v2 = replace(
        fx.egress,
        policy_version=2,
        allowed_https_hosts=("evidence.example.com",),
        registered_at=200,
    )
    fx.registry.register_egress(egress_v2)
    assert fx.registry.register_release(fx.release) == digest
    with pytest.raises(GovernanceError, match="egress policy is stale"):
        fx.registry.assert_release_current(fx.release)
    assert fx.registry.assess_release(fx.release, assessed_at=210).state is DeploymentState.INELIGIBLE


def test_tenant_isolation_drift_invalidates_release_currentness() -> None:
    fx = Fixture()
    fx.registry.register_release(fx.release)
    profile_v2 = replace(fx.tenant, profile_version=2, namespace_digest=D9, registered_at=200)
    fx.isolation.register_profile(profile_v2)
    with pytest.raises(GovernanceError):
        fx.registry.assert_release_current(fx.release)


def test_release_contract_rejects_version_mismatch_and_execution_claims() -> None:
    fx = Fixture()
    with pytest.raises(GovernanceError, match="release_version must equal package_version"):
        replace(fx.release, package_version="0.8.1")
    with pytest.raises(GovernanceError, match="cannot claim deployment"):
        replace(fx.release, deployment_performed=True)


def test_release_id_and_version_cannot_be_reused() -> None:
    fx = Fixture()
    fx.registry.register_release(fx.release)
    reused = replace(
        fx.release,
        release_sequence=2,
        source_commit_sha="b" * 40,
        released_at=190,
    )
    with pytest.raises(GovernanceError, match="release_id must not be reused"):
        fx.registry.register_release(reused)
