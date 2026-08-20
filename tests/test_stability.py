from dataclasses import replace

import pytest

from modelriskops.canonical import sha256_digest
from modelriskops.deployment import (
    DeploymentReleaseManifest,
    HttpsEgressPolicy,
    IsolatedWorkerProfile,
    ProductionDeploymentRegistry,
    RecoveryCheckpoint,
    RollbackPlan,
    RuntimeIdentityProfile,
    UpgradePlan,
)
from modelriskops.hardening import PostgresRlsPolicy, TenantEnvironment, TenantIsolationProfile, TenantIsolationRegistry
from modelriskops.models import GovernanceError
from modelriskops.stability import (
    BoundaryEvidenceReference,
    GovernanceBoundary,
    IndependentSecurityReviewChecklist,
    PublicSurfaceManifest,
    REQUIRED_SECURITY_REVIEW_ITEMS,
    REQUIRED_V1_NON_CLAIMS,
    ResponsibilityScope,
    SecurityReviewItem,
    SecurityReviewStatus,
    StableCompatibilityPolicy,
    StableReleaseBaseline,
    StableReleaseRegistry,
    SupportedUpgradePath,
)


def dg(label: str) -> str:
    return sha256_digest({"label": label})


class StableFixture:
    def __init__(self) -> None:
        self.isolation = TenantIsolationRegistry()
        self.rls = PostgresRlsPolicy(
            institution_id="bank-demo",
            policy_id="model-risk-evidence",
            policy_version=1,
            table_name="model_risk_evidence",
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
            database_role="modelriskops_runtime",
            namespace_digest=dg("namespace"),
            rls_policy_digests=(self.rls.evidence_digest,),
            registered_at=110,
        )
        self.isolation.register_profile(self.tenant)

        self.production = ProductionDeploymentRegistry(tenant_isolation_registry=self.isolation)
        self.identity = RuntimeIdentityProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=TenantEnvironment.PRODUCTION,
            workload_identity="modelriskops-prod",
            service_account="modelriskops-prod-sa",
            issuer_digest=dg("issuer"),
            audience_digest=dg("audience"),
            tenant_isolation_profile_digest=self.tenant.evidence_digest,
            registered_at=120,
        )
        self.production.register_identity(self.identity)
        self.egress = HttpsEgressPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_id="modelriskops-egress",
            policy_version=1,
            allowed_https_hosts=("evidence.example.com",),
            tls_required=True,
            default_deny=True,
            wildcard_hosts_allowed=False,
            raw_ip_egress_allowed=False,
            registered_at=130,
        )
        self.production.register_egress(self.egress)
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
        self.production.register_worker(self.worker)

        source_rollback = RollbackPlan(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v0.8",
            release_version="0.8.0", restore_artifact_digest=dg("v08-restore"),
            configuration_restore_digest=dg("v08-config"), data_recovery_procedure_digest=dg("v08-recovery"),
            rollback_validation_digest=dg("v08-rollback-test"), declared_at=150,
        )
        self.production.register_rollback(source_rollback)
        source_upgrade = UpgradePlan(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v0.8",
            release_version="0.8.0", source_release_digest=dg("pre-v08-release"),
            preflight_evidence_digest=dg("v08-preflight"), migration_evidence_digest=dg("v08-migration"),
            post_upgrade_validation_digest=dg("v08-post"), rollback_plan_digest=source_rollback.evidence_digest,
            backup_required=True, declared_at=160,
        )
        self.production.register_upgrade(source_upgrade)
        source_checkpoint = RecoveryCheckpoint(
            institution_id="bank-demo", tenant_id="tenant-a", checkpoint_id="pre-v08",
            release_id="modelriskops-v0.8", release_version="0.8.0",
            tenant_isolation_snapshot_digest=self.isolation.snapshot_digest("bank-demo", "tenant-a"),
            backup_artifact_digest=dg("v08-backup"), recovery_test_evidence_digest=dg("v08-recovery-test"), captured_at=170,
        )
        self.production.register_checkpoint(source_checkpoint)
        self.source_release = DeploymentReleaseManifest(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v0.8", release_sequence=1,
            release_version="0.8.0", source_commit_sha="a" * 40, package_version="0.8.0",
            wheel_sha256=dg("v08-wheel"), sbom_digest=dg("v08-sbom"), ci_evidence_digest=dg("v08-ci"),
            provenance_attestation_digest=dg("v08-provenance"), tenant_isolation_profile_digest=self.tenant.evidence_digest,
            runtime_identity_profile_digest=self.identity.evidence_digest, egress_policy_digest=self.egress.evidence_digest,
            worker_profile_digest=self.worker.evidence_digest, rollback_plan_digest=source_rollback.evidence_digest,
            upgrade_plan_digest=source_upgrade.evidence_digest, recovery_checkpoint_digest=source_checkpoint.evidence_digest,
            released_at=180,
        )
        self.production.register_release(self.source_release)

        target_rollback = RollbackPlan(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v1",
            release_version="1.0.0", restore_artifact_digest=dg("v1-restore"),
            configuration_restore_digest=dg("v1-config"), data_recovery_procedure_digest=dg("v1-recovery"),
            rollback_validation_digest=dg("v1-rollback-test"), declared_at=200,
        )
        self.production.register_rollback(target_rollback)
        target_upgrade = UpgradePlan(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v1",
            release_version="1.0.0", source_release_digest=self.source_release.evidence_digest,
            preflight_evidence_digest=dg("v1-preflight"), migration_evidence_digest=dg("v1-migration"),
            post_upgrade_validation_digest=dg("v1-post"), rollback_plan_digest=target_rollback.evidence_digest,
            backup_required=True, declared_at=210,
        )
        self.production.register_upgrade(target_upgrade)
        target_checkpoint = RecoveryCheckpoint(
            institution_id="bank-demo", tenant_id="tenant-a", checkpoint_id="pre-v1",
            release_id="modelriskops-v1", release_version="1.0.0",
            tenant_isolation_snapshot_digest=self.isolation.snapshot_digest("bank-demo", "tenant-a"),
            backup_artifact_digest=dg("v1-backup"), recovery_test_evidence_digest=dg("v1-recovery-test"), captured_at=220,
        )
        self.production.register_checkpoint(target_checkpoint)
        self.target_release = DeploymentReleaseManifest(
            institution_id="bank-demo", tenant_id="tenant-a", release_id="modelriskops-v1", release_sequence=2,
            release_version="1.0.0", source_commit_sha="b" * 40, package_version="1.0.0",
            wheel_sha256=dg("v1-wheel"), sbom_digest=dg("v1-sbom"), ci_evidence_digest=dg("v1-ci"),
            provenance_attestation_digest=dg("v1-provenance"), tenant_isolation_profile_digest=self.tenant.evidence_digest,
            runtime_identity_profile_digest=self.identity.evidence_digest, egress_policy_digest=self.egress.evidence_digest,
            worker_profile_digest=self.worker.evidence_digest, rollback_plan_digest=target_rollback.evidence_digest,
            upgrade_plan_digest=target_upgrade.evidence_digest, recovery_checkpoint_digest=target_checkpoint.evidence_digest,
            released_at=230,
        )
        self.production.register_release(self.target_release)

        self.compatibility = StableCompatibilityPolicy(
            stable_since_version="1.0.0", compatibility_series="1.x", semver_required=True,
            breaking_change_requires_major=True, python_symbol_removal_requires_major=True,
            cli_command_removal_requires_major=True, json_schema_removal_requires_major=True,
            json_required_field_removal_requires_major=True, json_enum_value_removal_requires_major=True,
            unknown_json_fields_rejected=True, deprecation_min_minor_releases=2, declared_at=240,
        )
        self.surface = PublicSurfaceManifest(
            release_version="1.0.0", compatibility_policy_digest=self.compatibility.evidence_digest,
            python_api_symbols=("ModelRecord", "StableReleaseBaseline"),
            cli_commands=("contract-snapshot", "verify-dossier"),
            json_schema_baseline_digest=dg("schema-baseline"), generated_at=250,
        )
        self.upgrade_path = SupportedUpgradePath(
            source_series="0.8.x", target_version="1.0.0",
            source_release_digest=self.source_release.evidence_digest,
            target_release_digest=self.target_release.evidence_digest,
            preflight_evidence_digest=dg("stable-preflight"), migration_evidence_digest=dg("stable-migration"),
            post_upgrade_validation_digest=dg("stable-post"), rollback_evidence_digest=dg("stable-rollback"),
            backup_required=True, breaking_changes_declared=False, declared_at=260,
        )
        items = tuple(
            SecurityReviewItem(
                item_id=item_id,
                status=SecurityReviewStatus.CLOSED,
                evidence_digest=dg(f"review-evidence-{item_id}"),
                reviewer_rationale_digest=dg(f"review-rationale-{item_id}"),
            )
            for item_id in REQUIRED_SECURITY_REVIEW_ITEMS
        )
        self.review = IndependentSecurityReviewChecklist(
            release_version="1.0.0", reviewed_repository_digest=dg("reviewed-repository"),
            reviewer_id="independent-reviewer", reviewer_independence_confirmed=True,
            items=items, reviewed_at=270,
        )
        self.scope = ResponsibilityScope(
            release_version="1.0.0", legal_advice_provided=False, regulatory_compliance_determined=False,
            certification_claimed=False, supervisory_acceptance_claimed=False, production_fitness_claimed=False,
            institution_legal_review_required=True, privacy_data_protection_review_required=True,
            model_risk_accountable_owner_required=True, production_iam_network_review_required=True,
            records_retention_review_required=True, non_claims=REQUIRED_V1_NON_CLAIMS, declared_at=280,
        )
        boundaries = tuple(
            BoundaryEvidenceReference(
                boundary=boundary,
                artifact_digest=dg(f"boundary-artifact-{boundary.value}"),
                evidence_description_digest=dg(f"boundary-description-{boundary.value}"),
            )
            for boundary in GovernanceBoundary
        )
        self.baseline = StableReleaseBaseline(
            release_version="1.0.0", compatibility_policy_digest=self.compatibility.evidence_digest,
            public_surface_manifest_digest=self.surface.evidence_digest,
            production_release_manifest_digest=self.target_release.evidence_digest,
            supported_upgrade_path_digest=self.upgrade_path.evidence_digest,
            security_review_checklist_digest=self.review.evidence_digest,
            responsibility_scope_digest=self.scope.evidence_digest,
            reproducible_checksum_manifest_digest=dg("checksums"),
            provenance_attestation_digest=self.target_release.provenance_attestation_digest,
            boundary_evidence=boundaries, assembled_at=290,
        )
        self.stable = StableReleaseRegistry(production_registry=self.production)

    def register(self) -> str:
        return self.stable.register_baseline(
            source_release=self.source_release,
            target_release=self.target_release,
            compatibility_policy=self.compatibility,
            public_surface=self.surface,
            upgrade_path=self.upgrade_path,
            security_review=self.review,
            responsibility_scope=self.scope,
            baseline=self.baseline,
        )


def test_complete_v1_baseline_registers_and_is_current() -> None:
    fx = StableFixture()
    digest = fx.register()
    assert digest == fx.baseline.evidence_digest
    assert fx.register() == digest
    fx.stable.assert_baseline_current(
        baseline=fx.baseline,
        source_release=fx.source_release,
        target_release=fx.target_release,
        upgrade_path=fx.upgrade_path,
    )


def test_review_contract_rejects_missing_items_false_independence_and_bad_repository_digest() -> None:
    fx = StableFixture()
    with pytest.raises(GovernanceError, match="every required v1 item"):
        replace(fx.review, items=fx.review.items[:-1])
    with pytest.raises(GovernanceError, match="independence"):
        replace(fx.review, reviewer_independence_confirmed=False)
    with pytest.raises(GovernanceError, match="reviewed_repository_digest"):
        replace(fx.review, reviewed_repository_digest="not-a-digest")


def test_risk_acceptance_requires_accountable_human_and_digest() -> None:
    fx = StableFixture()
    with pytest.raises(GovernanceError):
        replace(fx.review.items[0], status=SecurityReviewStatus.RISK_ACCEPTED)
    accepted = replace(
        fx.review.items[0], status=SecurityReviewStatus.RISK_ACCEPTED,
        risk_acceptance_human_id="model-risk-owner", risk_acceptance_digest=dg("accepted-risk"),
    )
    assert accepted.status is SecurityReviewStatus.RISK_ACCEPTED


def test_review_and_baseline_cannot_backdate_readiness() -> None:
    fx = StableFixture()
    early_review = replace(fx.review, reviewed_at=229)
    early_baseline = replace(fx.baseline, security_review_checklist_digest=early_review.evidence_digest)
    with pytest.raises(GovernanceError, match="review cannot predate"):
        fx.stable.register_baseline(
            source_release=fx.source_release,
            target_release=fx.target_release,
            compatibility_policy=fx.compatibility,
            public_surface=fx.surface,
            upgrade_path=fx.upgrade_path,
            security_review=early_review,
            responsibility_scope=fx.scope,
            baseline=early_baseline,
        )


def test_exact_source_release_is_required_for_currentness() -> None:
    fx = StableFixture()
    fx.register()
    substituted = replace(fx.source_release, source_commit_sha="c" * 40)
    with pytest.raises(GovernanceError, match="source release is not registered"):
        fx.stable.assert_baseline_current(
            baseline=fx.baseline,
            source_release=substituted,
            target_release=fx.target_release,
            upgrade_path=fx.upgrade_path,
        )


def test_target_release_drift_invalidates_stable_currentness_but_not_history() -> None:
    fx = StableFixture()
    digest = fx.register()
    egress_v2 = replace(fx.egress, policy_version=2, allowed_https_hosts=("archive.example.com",), registered_at=300)
    fx.production.register_egress(egress_v2)
    assert fx.register() == digest
    with pytest.raises(GovernanceError):
        fx.stable.assert_baseline_current(
            baseline=fx.baseline,
            source_release=fx.source_release,
            target_release=fx.target_release,
            upgrade_path=fx.upgrade_path,
        )
