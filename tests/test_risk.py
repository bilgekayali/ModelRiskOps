import pytest

from modelriskops import (
    ControlObservation,
    ControlStrength,
    FactorLevel,
    FactorName,
    GovernanceError,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    RiskFactor,
    RiskPolicyProfile,
    assess_model_risk,
    default_policy,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def record() -> ModelRecord:
    return ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="risk-owner-17",
        business_use="Credit underwriting decision support",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.VALIDATION,
        deployment_context="Internal underwriting service",
        intended_users=("credit-risk-team",),
        prohibited_uses=("fully-autonomous-decline",),
    )


def version(version_id: str = "2026.08.1", artifact_digest: str = D1) -> ModelVersion:
    return ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id=version_id,
        artifact_digest=artifact_digest,
        code_digest=D2,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
    )


def factors(level: FactorLevel) -> tuple[RiskFactor, ...]:
    return tuple(RiskFactor(factor=name, level=level) for name in FactorName)


def mixed_high_factors() -> tuple[RiskFactor, ...]:
    levels = {
        FactorName.DECISION_IMPACT: FactorLevel.CRITICAL,
        FactorName.CUSTOMER_FINANCIAL_IMPACT: FactorLevel.CRITICAL,
        FactorName.AUTONOMY: FactorLevel.HIGH,
        FactorName.COMPLEXITY: FactorLevel.MODERATE,
        FactorName.DATA_SENSITIVITY: FactorLevel.MODERATE,
        FactorName.EXTERNAL_DEPENDENCY: FactorLevel.MODERATE,
        FactorName.EXPLAINABILITY_NEED: FactorLevel.MODERATE,
        FactorName.REGULATORY_RELEVANCE: FactorLevel.HIGH,
        FactorName.DEPLOYMENT_CRITICALITY: FactorLevel.HIGH,
    }
    return tuple(RiskFactor(factor=name, level=levels[name]) for name in FactorName)


def test_identical_inputs_produce_identical_decision_digest() -> None:
    policy = default_policy("bank-a")
    first = assess_model_risk(record(), version(), factors(FactorLevel.MODERATE), (), policy)
    second = assess_model_risk(record(), version(), reversed(factors(FactorLevel.MODERATE)), (), policy)
    assert first == second
    assert first.evidence_digest == second.evidence_digest


def test_missing_factor_fails_closed_instead_of_defaulting_low() -> None:
    assessment = factors(FactorLevel.MODERATE)[:-1]
    with pytest.raises(GovernanceError, match="exactly one value for every required factor"):
        assess_model_risk(record(), version(), assessment, (), default_policy("bank-a"))


def test_high_impact_combination_cannot_resolve_to_low_risk() -> None:
    decision = assess_model_risk(
        record(),
        version(),
        mixed_high_factors(),
        (),
        default_policy("bank-a"),
    )
    assert decision.inherent_tier.value in {"high", "critical"}
    assert decision.residual_tier.value in {"high", "critical"}
    assert "independent_validation" in decision.requirements
    assert "senior_risk_approval" in decision.requirements


def test_control_credit_is_bounded_by_policy() -> None:
    controls = tuple(
        ControlObservation(
            control_id=f"control-{index}",
            strength=ControlStrength.STRONG,
            evidence_digest=f"{index:x}" * 64,
        )
        for index in range(1, 7)
    )
    decision = assess_model_risk(
        record(),
        version(),
        mixed_high_factors(),
        controls,
        default_policy("bank-a"),
    )
    assert decision.control_credit == 12
    assert decision.residual_score == decision.inherent_score - 12
    assert decision.residual_tier.value == "high"


def test_policy_change_rebinds_decision() -> None:
    original = default_policy("bank-a")
    changed = RiskPolicyProfile(
        institution_id=original.institution_id,
        policy_id=original.policy_id,
        version="2",
        weights=original.weights,
        medium_threshold=20,
        high_threshold=44,
        critical_threshold=68,
        max_control_credit=original.max_control_credit,
        requirement_sets=original.requirement_sets,
    )
    first = assess_model_risk(record(), version(), factors(FactorLevel.MODERATE), (), original)
    second = assess_model_risk(record(), version(), factors(FactorLevel.MODERATE), (), changed)
    assert first.policy_digest != second.policy_digest
    assert first.evidence_digest != second.evidence_digest


def test_different_model_version_rebinds_decision() -> None:
    policy = default_policy("bank-a")
    first = assess_model_risk(record(), version(), factors(FactorLevel.MODERATE), (), policy)
    second = assess_model_risk(
        record(),
        version(version_id="2026.08.2", artifact_digest="a" * 64),
        factors(FactorLevel.MODERATE),
        (),
        policy,
    )
    assert first.model_version_digest != second.model_version_digest
    assert first.evidence_digest != second.evidence_digest


def test_cross_institution_policy_fails_closed() -> None:
    with pytest.raises(GovernanceError, match="not applicable"):
        assess_model_risk(
            record(),
            version(),
            factors(FactorLevel.MODERATE),
            (),
            default_policy("bank-b"),
        )


def test_duplicate_control_id_is_rejected() -> None:
    control = ControlObservation(
        control_id="monitoring",
        strength=ControlStrength.ADEQUATE,
        evidence_digest=D5,
    )
    with pytest.raises(GovernanceError, match="must not repeat control_id"):
        assess_model_risk(
            record(),
            version(),
            factors(FactorLevel.MODERATE),
            (control, control),
            default_policy("bank-a"),
        )
