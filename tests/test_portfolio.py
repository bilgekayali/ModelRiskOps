from dataclasses import replace

import pytest

from modelriskops.models import InventoryRegistry, ModelRecord, ModelType, ModelVersion, LifecycleState, GovernanceError
from modelriskops.portfolio import (
    DataAccessLevel,
    DependencyMateriality,
    PortfolioAssessmentState,
    PortfolioPosition,
    PortfolioRiskPolicy,
    PortfolioRiskRegistry,
    PortfolioSnapshot,
    Substitutability,
    ThirdPartyExitPlan,
    ThirdPartyModelDependency,
    ThirdPartyProviderProfile,
    default_portfolio_risk_policy,
)
from modelriskops.risk import RiskDecision, RiskTier


D0 = "0" * 64
D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64
D7 = "7" * 64
D8 = "8" * 64
D9 = "9" * 64
DA = "a" * 64
DB = "b" * 64
DC = "c" * 64
DD = "d" * 64
DE = "e" * 64
DF = "f" * 64


def make_model(model_id: str) -> ModelRecord:
    return ModelRecord(
        institution_id="bank-demo",
        model_id=model_id,
        name=model_id.upper(),
        owner_id=f"owner-{model_id}",
        business_use=f"business-use-{model_id}",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.DEPLOYED,
        deployment_context="production",
    )


def make_version(model_id: str, suffix: str) -> ModelVersion:
    return ModelVersion(
        institution_id="bank-demo",
        model_id=model_id,
        version_id="1",
        artifact_digest=suffix * 64,
        code_digest=("a" if suffix != "a" else "b") * 64,
        data_digest=("c" if suffix != "c" else "d") * 64,
        config_digest=("e" if suffix != "e" else "f") * 64,
        provenance_source=f"registry://{model_id}/1",
    )


def make_risk(record: ModelRecord, version: ModelVersion, tier: RiskTier, suffix: str) -> RiskDecision:
    return RiskDecision(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        model_digest=record.evidence_digest,
        model_version_digest=version.evidence_digest,
        policy_digest=suffix * 64,
        inherent_score=10,
        inherent_tier=tier,
        control_credit=0,
        residual_score=10,
        residual_tier=tier,
        contributions=(),
        requirements=(),
    )


class PortfolioFixture:
    def __init__(self, *, register_material_exit: bool = True, tested_critical: bool = True) -> None:
        self.inventory = InventoryRegistry()
        self.records = {model_id: make_model(model_id) for model_id in ("model-a", "model-b", "model-c")}
        self.versions = {
            "model-a": make_version("model-a", "1"),
            "model-b": make_version("model-b", "2"),
            "model-c": make_version("model-c", "3"),
        }
        for model_id in ("model-a", "model-b", "model-c"):
            self.inventory.register_model(self.records[model_id])
            self.inventory.register_version(self.versions[model_id])

        self.risks = {
            "model-a": make_risk(self.records["model-a"], self.versions["model-a"], RiskTier.HIGH, "4"),
            "model-b": make_risk(self.records["model-b"], self.versions["model-b"], RiskTier.MEDIUM, "5"),
            "model-c": make_risk(self.records["model-c"], self.versions["model-c"], RiskTier.LOW, "6"),
        }
        self.registry = PortfolioRiskRegistry(self.inventory)
        self.provider = ThirdPartyProviderProfile(
            institution_id="bank-demo",
            provider_id="provider-x",
            profile_version=1,
            legal_name="Provider X Ltd",
            accountable_owner_id="vendor-owner",
            service_jurisdictions=("EU", "TR"),
            due_diligence_evidence_digest=D1,
            contract_evidence_digest=D2,
            security_assurance_evidence_digest=D3,
            financial_resilience_evidence_digest=D4,
            due_diligence_expires_at=1000,
            contract_expires_at=1100,
            registered_at=100,
        )
        self.registry.register_provider_profile(self.provider)
        self.dep_a = ThirdPartyModelDependency(
            institution_id="bank-demo",
            model_id="model-a",
            version_id="1",
            dependency_id="vendor-service-a",
            dependency_version=1,
            model_version_digest=self.versions["model-a"].evidence_digest,
            provider_id="provider-x",
            provider_profile_digest=self.provider.evidence_digest,
            provider_model_id="vendor-model-a",
            provider_model_version="2026.08",
            provider_version_evidence_digest=D0,
            service_id="api-a",
            service_description_digest=D5,
            materiality=DependencyMateriality.CRITICAL,
            substitutability=Substitutability.HIGH,
            data_access_level=DataAccessLevel.PERSONAL,
            registered_at=110,
        )
        self.dep_a2 = ThirdPartyModelDependency(
            institution_id="bank-demo",
            model_id="model-a",
            version_id="1",
            dependency_id="vendor-service-a-secondary",
            dependency_version=1,
            model_version_digest=self.versions["model-a"].evidence_digest,
            provider_id="provider-x",
            provider_profile_digest=self.provider.evidence_digest,
            provider_model_id="vendor-model-a",
            provider_model_version="2026.08",
            provider_version_evidence_digest=D0,
            service_id="api-a-secondary",
            service_description_digest=D6,
            materiality=DependencyMateriality.NON_MATERIAL,
            substitutability=Substitutability.MODERATE,
            data_access_level=DataAccessLevel.NON_SENSITIVE,
            registered_at=111,
        )
        self.dep_b = ThirdPartyModelDependency(
            institution_id="bank-demo",
            model_id="model-b",
            version_id="1",
            dependency_id="vendor-service-b",
            dependency_version=1,
            model_version_digest=self.versions["model-b"].evidence_digest,
            provider_id="provider-x",
            provider_profile_digest=self.provider.evidence_digest,
            provider_model_id="vendor-model-b",
            provider_model_version="2026.07",
            provider_version_evidence_digest=D4,
            service_id="api-b",
            service_description_digest=D7,
            materiality=DependencyMateriality.MATERIAL,
            substitutability=Substitutability.MODERATE,
            data_access_level=DataAccessLevel.SENSITIVE,
            registered_at=112,
        )
        for dependency in (self.dep_a, self.dep_a2, self.dep_b):
            self.registry.register_dependency(dependency)

        self.exit_a = ThirdPartyExitPlan(
            institution_id="bank-demo",
            model_id="model-a",
            version_id="1",
            dependency_id=self.dep_a.dependency_id,
            dependency_digest=self.dep_a.evidence_digest,
            plan_version=1,
            owner_id="exit-owner-a",
            transition_strategy_digest=D8,
            portability_evidence_digest=D9,
            validation_plan_digest=DA,
            max_exit_seconds=86400,
            created_at=120,
            tested_at=130 if tested_critical else None,
            test_evidence_digest=DB if tested_critical else None,
        )
        self.registry.register_exit_plan(self.exit_a)
        self.exit_b = ThirdPartyExitPlan(
            institution_id="bank-demo",
            model_id="model-b",
            version_id="1",
            dependency_id=self.dep_b.dependency_id,
            dependency_digest=self.dep_b.evidence_digest,
            plan_version=1,
            owner_id="exit-owner-b",
            transition_strategy_digest=DC,
            portability_evidence_digest=DD,
            validation_plan_digest=DE,
            max_exit_seconds=172800,
            created_at=121,
        )
        if register_material_exit:
            self.registry.register_exit_plan(self.exit_b)

        self.snapshot = PortfolioSnapshot(
            institution_id="bank-demo",
            portfolio_id="enterprise-model-portfolio",
            snapshot_version=1,
            inventory_snapshot_digest=self.inventory.snapshot_digest(),
            positions=(
                PortfolioPosition(
                    institution_id="bank-demo",
                    model_id="model-a",
                    version_id="1",
                    model_version_digest=self.versions["model-a"].evidence_digest,
                    risk_decision_digest=self.risks["model-a"].evidence_digest,
                    residual_risk_tier=RiskTier.HIGH,
                    exposure_weight_bps=5000,
                    third_party_dependency_digests=tuple(sorted((self.dep_a.evidence_digest, self.dep_a2.evidence_digest))),
                ),
                PortfolioPosition(
                    institution_id="bank-demo",
                    model_id="model-b",
                    version_id="1",
                    model_version_digest=self.versions["model-b"].evidence_digest,
                    risk_decision_digest=self.risks["model-b"].evidence_digest,
                    residual_risk_tier=RiskTier.MEDIUM,
                    exposure_weight_bps=3000,
                    third_party_dependency_digests=(self.dep_b.evidence_digest,),
                ),
                PortfolioPosition(
                    institution_id="bank-demo",
                    model_id="model-c",
                    version_id="1",
                    model_version_digest=self.versions["model-c"].evidence_digest,
                    risk_decision_digest=self.risks["model-c"].evidence_digest,
                    residual_risk_tier=RiskTier.LOW,
                    exposure_weight_bps=2000,
                ),
            ),
            as_of_time=150,
        )
        self.registry.register_snapshot(self.snapshot, self.risks.values())


def permissive_policy() -> PortfolioRiskPolicy:
    return PortfolioRiskPolicy(
        institution_id="bank-demo",
        policy_id="portfolio-permissive",
        version="1",
        single_provider_warning_bps=9000,
        single_provider_limit_bps=9500,
        high_critical_exposure_limit_bps=9000,
        require_exit_plan_for_material=True,
        require_tested_exit_for_critical=True,
        degrade_low_substitutability=True,
    )


def test_provider_profiles_and_dependencies_are_versioned_and_exact() -> None:
    fx = PortfolioFixture()
    provider_v2 = replace(
        fx.provider,
        profile_version=2,
        due_diligence_evidence_digest=DF,
        registered_at=200,
        due_diligence_expires_at=1200,
        contract_expires_at=1300,
    )
    fx.registry.register_provider_profile(provider_v2)
    with pytest.raises(GovernanceError, match="provider profile is stale"):
        fx.registry.assert_dependency_current(fx.dep_a)

    dep_v2 = replace(
        fx.dep_a,
        dependency_version=2,
        provider_profile_digest=provider_v2.evidence_digest,
        provider_model_version="2026.09",
        provider_version_evidence_digest=DF,
        registered_at=210,
    )
    fx.registry.register_dependency(dep_v2)
    fx.registry.assert_dependency_current(dep_v2)
    with pytest.raises(GovernanceError, match="third-party dependency is stale"):
        fx.registry.assert_dependency_current(fx.dep_a)


def test_dependency_rejects_cross_model_and_stale_provider_binding() -> None:
    fx = PortfolioFixture()
    wrong_model = replace(
        fx.dep_a,
        dependency_id="wrong-model",
        dependency_version=1,
        model_id="model-b",
        model_version_digest=fx.versions["model-a"].evidence_digest,
    )
    with pytest.raises(GovernanceError, match="model-version digest"):
        fx.registry.register_dependency(wrong_model)

    provider_v2 = replace(
        fx.provider,
        profile_version=2,
        registered_at=200,
        due_diligence_expires_at=1200,
        contract_expires_at=1300,
    )
    fx.registry.register_provider_profile(provider_v2)
    stale = replace(
        fx.dep_b,
        dependency_id="stale-new-dependency",
        dependency_version=1,
        registered_at=210,
    )
    with pytest.raises(GovernanceError, match="current provider profile"):
        fx.registry.register_dependency(stale)


def test_exit_plan_requires_exact_current_dependency_and_testing_pair() -> None:
    fx = PortfolioFixture()
    with pytest.raises(GovernanceError, match="supplied together"):
        replace(fx.exit_a, tested_at=140, test_evidence_digest=None)
    backdated = replace(fx.exit_a, plan_version=2, created_at=105)
    with pytest.raises(GovernanceError, match="cannot predate"):
        fx.registry.register_exit_plan(backdated)


def test_portfolio_weights_and_risk_decision_binding_fail_closed() -> None:
    fx = PortfolioFixture()
    bad_position = replace(fx.snapshot.positions[0], exposure_weight_bps=4999)
    with pytest.raises(GovernanceError, match="exactly 10000"):
        replace(fx.snapshot, positions=(bad_position,) + fx.snapshot.positions[1:])

    fresh = PortfolioRiskRegistry(fx.inventory)
    fresh.register_provider_profile(fx.provider)
    for dependency in (fx.dep_a, fx.dep_a2, fx.dep_b):
        fresh.register_dependency(dependency)
    bad_risk = replace(fx.risks["model-a"], residual_tier=RiskTier.CRITICAL)
    bad_risk_position = replace(
        fx.snapshot.positions[0],
        risk_decision_digest=bad_risk.evidence_digest,
    )
    bad_snapshot = replace(
        fx.snapshot,
        positions=(bad_risk_position,) + fx.snapshot.positions[1:],
    )
    with pytest.raises(GovernanceError, match="residual risk tier"):
        fresh.register_snapshot(bad_snapshot, (bad_risk, fx.risks["model-b"], fx.risks["model-c"]))


def test_provider_concentration_counts_model_exposure_once_per_provider() -> None:
    fx = PortfolioFixture()
    assessment = fx.registry.assess_portfolio(fx.snapshot, default_portfolio_risk_policy("bank-demo"), assessed_at=160)
    assert assessment.state is PortfolioAssessmentState.BREACHED
    assert assessment.third_party_exposure_bps == 8000
    assert assessment.high_critical_exposure_bps == 5000
    assert assessment.critical_provider_ids == ("provider-x",)
    assert len(assessment.provider_exposures) == 1
    row = assessment.provider_exposures[0]
    assert row.provider_id == "provider-x"
    assert row.exposure_bps == 8000
    assert row.model_count == 2
    assert row.dependency_count == 3
    assert "provider_concentration_breach:provider-x:8000" in assessment.findings


def test_current_complete_evidence_can_assess_healthy() -> None:
    fx = PortfolioFixture()
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=160)
    assert assessment.state is PortfolioAssessmentState.HEALTHY
    assert assessment.critical_provider_ids == ("provider-x",)
    assert assessment.findings == ()


def test_missing_material_exit_plan_fails_as_incomplete() -> None:
    fx = PortfolioFixture(register_material_exit=False)
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=160)
    assert assessment.state is PortfolioAssessmentState.INCOMPLETE
    assert "missing_current_exit_plan:vendor-service-b" in assessment.findings


def test_untested_critical_exit_plan_fails_as_incomplete() -> None:
    fx = PortfolioFixture(tested_critical=False)
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=160)
    assert assessment.state is PortfolioAssessmentState.INCOMPLETE
    assert "untested_critical_exit_plan:vendor-service-a" in assessment.findings


def test_expired_provider_evidence_fails_as_incomplete() -> None:
    fx = PortfolioFixture()
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=1000)
    assert assessment.state is PortfolioAssessmentState.INCOMPLETE
    assert "provider_due_diligence_expired:provider-x" in assessment.findings


def test_low_substitutability_degrades_without_claiming_vendor_unsafety() -> None:
    fx = PortfolioFixture()
    dep_b_v2 = replace(
        fx.dep_b,
        dependency_version=2,
        substitutability=Substitutability.LOW,
        registered_at=140,
    )
    fx.registry.register_dependency(dep_b_v2)
    exit_b_v2 = replace(
        fx.exit_b,
        dependency_digest=dep_b_v2.evidence_digest,
        plan_version=2,
        created_at=141,
    )
    fx.registry.register_exit_plan(exit_b_v2)
    snapshot_v2 = replace(
        fx.snapshot,
        snapshot_version=2,
        positions=(
            fx.snapshot.positions[0],
            replace(fx.snapshot.positions[1], third_party_dependency_digests=(dep_b_v2.evidence_digest,)),
            fx.snapshot.positions[2],
        ),
        as_of_time=170,
    )
    fx.registry.register_snapshot(snapshot_v2, fx.risks.values())
    assessment = fx.registry.assess_portfolio(snapshot_v2, permissive_policy(), assessed_at=180)
    assert assessment.state is PortfolioAssessmentState.DEGRADED
    assert "low_substitutability:vendor-service-b" in assessment.findings


def test_provider_profile_drift_invalidates_registered_snapshot_currentness() -> None:
    fx = PortfolioFixture()
    fx.registry.assert_snapshot_current(fx.snapshot)
    provider_v2 = replace(
        fx.provider,
        profile_version=2,
        registered_at=200,
        due_diligence_expires_at=1200,
        contract_expires_at=1300,
    )
    fx.registry.register_provider_profile(provider_v2)
    with pytest.raises(GovernanceError, match="provider profile is stale"):
        fx.registry.assert_snapshot_current(fx.snapshot)


def test_inventory_drift_invalidates_registered_snapshot_currentness() -> None:
    fx = PortfolioFixture()
    new_record = make_model("model-d")
    new_version = make_version("model-d", "7")
    fx.inventory.register_model(new_record)
    fx.inventory.register_version(new_version)
    with pytest.raises(GovernanceError, match="inventory snapshot is stale"):
        fx.registry.assert_snapshot_current(fx.snapshot)


def test_exact_historical_retries_remain_idempotent_after_provider_drift() -> None:
    fx = PortfolioFixture()
    provider_v2 = replace(
        fx.provider,
        profile_version=2,
        due_diligence_evidence_digest=DF,
        registered_at=200,
        due_diligence_expires_at=1200,
        contract_expires_at=1300,
    )
    fx.registry.register_provider_profile(provider_v2)
    assert fx.registry.register_dependency(fx.dep_a) == fx.dep_a.evidence_digest
    assert fx.registry.register_exit_plan(fx.exit_a) == fx.exit_a.evidence_digest
    assert fx.registry.register_snapshot(fx.snapshot, fx.risks.values()) == fx.snapshot.evidence_digest
    with pytest.raises(GovernanceError, match="different content"):
        fx.registry.register_dependency(replace(fx.dep_a, service_description_digest=DF))
    with pytest.raises(GovernanceError, match="different content"):
        fx.registry.register_snapshot(replace(fx.snapshot, as_of_time=151), fx.risks.values())


def test_exact_historical_snapshot_retry_remains_idempotent_after_inventory_drift() -> None:
    fx = PortfolioFixture()
    new_record = make_model("model-d")
    new_version = make_version("model-d", "7")
    fx.inventory.register_model(new_record)
    fx.inventory.register_version(new_version)
    assert fx.registry.register_snapshot(fx.snapshot, fx.risks.values()) == fx.snapshot.evidence_digest
    with pytest.raises(GovernanceError, match="inventory snapshot is stale"):
        fx.registry.assert_snapshot_current(fx.snapshot)


def test_evidence_package_reproduces_exact_current_portfolio_state() -> None:
    fx = PortfolioFixture()
    policy = permissive_policy()
    assessment = fx.registry.assess_portfolio(fx.snapshot, policy, assessed_at=160)
    package = fx.registry.build_evidence_package(fx.snapshot, policy, assessment, generated_at=170)
    assert package.state is PortfolioAssessmentState.HEALTHY
    assert package.provider_profile_digests == (fx.provider.evidence_digest,)
    assert package.dependency_digests == tuple(sorted((fx.dep_a.evidence_digest, fx.dep_a2.evidence_digest, fx.dep_b.evidence_digest)))
    assert package.exit_plan_digests == tuple(sorted((fx.exit_a.evidence_digest, fx.exit_b.evidence_digest)))
    fx.registry.verify_evidence_package(package, fx.snapshot, policy, assessment)
    with pytest.raises(GovernanceError, match="does not reproduce"):
        fx.registry.verify_evidence_package(replace(package, assessment_digest=DF), fx.snapshot, policy, assessment)
