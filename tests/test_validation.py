import pytest

from modelriskops import (
    FactorLevel,
    FactorName,
    FindingSeverity,
    FindingStatus,
    GovernanceError,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    RiskFactor,
    TestStatus,
    ValidationConclusion,
    ValidationDomain,
    ValidationFinding,
    ValidationTest,
    assess_model_risk,
    build_validation_plan,
    default_policy,
    resolve_validation,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64


def record() -> ModelRecord:
    return ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="model-owner",
        business_use="Credit underwriting decision support",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.VALIDATION,
        deployment_context="Internal underwriting service",
    )


def version(artifact_digest: str = D1) -> ModelVersion:
    return ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="2026.08.1",
        artifact_digest=artifact_digest,
        code_digest=D2,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
    )


def high_risk_decision():
    factors = tuple(
        RiskFactor(factor=factor, level=FactorLevel.CRITICAL)
        for factor in FactorName
    )
    return assess_model_risk(
        record(),
        version(),
        factors,
        (),
        default_policy("bank-a"),
    )


def passed_tests() -> tuple[ValidationTest, ...]:
    return (
        ValidationTest(
            test_id="concept",
            domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
            mandatory=True,
            status=TestStatus.PASS,
            evidence_digest=D5,
        ),
        ValidationTest(
            test_id="performance",
            domain=ValidationDomain.PERFORMANCE,
            mandatory=True,
            status=TestStatus.PASS,
            evidence_digest=D6,
        ),
    )


def plan(tests=None):
    return build_validation_plan(
        record(),
        version(),
        high_risk_decision(),
        validator_id="independent-validator",
        validator_role="model-validation",
        independent_from_owner=True,
        tests=tests or passed_tests(),
    )


def test_high_risk_model_requires_independent_validator() -> None:
    with pytest.raises(GovernanceError, match="requires independent validation"):
        build_validation_plan(
            record(),
            version(),
            high_risk_decision(),
            validator_id="validation-team",
            validator_role="model-validation",
            independent_from_owner=False,
            tests=passed_tests(),
        )


def test_model_owner_cannot_self_validate_when_independence_required() -> None:
    with pytest.raises(GovernanceError, match="owner cannot serve"):
        build_validation_plan(
            record(),
            version(),
            high_risk_decision(),
            validator_id="model-owner",
            validator_role="model-validation",
            independent_from_owner=True,
            tests=passed_tests(),
        )


def test_stale_risk_decision_cannot_validate_changed_model_version() -> None:
    with pytest.raises(GovernanceError, match="stale for model version"):
        build_validation_plan(
            record(),
            version(artifact_digest="a" * 64),
            high_risk_decision(),
            validator_id="independent-validator",
            validator_role="model-validation",
            independent_from_owner=True,
            tests=passed_tests(),
        )


def test_incomplete_mandatory_test_yields_incomplete() -> None:
    tests = (
        ValidationTest(
            test_id="concept",
            domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
            mandatory=True,
            status=TestStatus.NOT_STARTED,
        ),
    )
    resolution = resolve_validation(plan(tests), ())
    assert resolution.conclusion is ValidationConclusion.INCOMPLETE


def test_failed_mandatory_test_prevents_pass() -> None:
    tests = (
        ValidationTest(
            test_id="concept",
            domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
            mandatory=True,
            status=TestStatus.FAIL,
            evidence_digest=D5,
        ),
    )
    resolution = resolve_validation(plan(tests), ())
    assert resolution.conclusion is ValidationConclusion.FAIL


def test_open_high_finding_prevents_pass() -> None:
    finding = ValidationFinding(
        finding_id="F-001",
        test_id="concept",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        evidence_digest=D5,
        description="Conceptual limitation remains unresolved.",
    )
    resolution = resolve_validation(plan(), (finding,))
    assert resolution.conclusion is ValidationConclusion.FAIL
    assert resolution.blocking_finding_ids == ("F-001",)


def test_open_medium_finding_yields_pass_with_conditions() -> None:
    finding = ValidationFinding(
        finding_id="F-002",
        test_id="performance",
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.OPEN,
        evidence_digest=D5,
        description="Monitoring threshold requires follow-up.",
    )
    resolution = resolve_validation(plan(), (finding,))
    assert resolution.conclusion is ValidationConclusion.PASS_WITH_CONDITIONS
    assert resolution.open_finding_ids == ("F-002",)


def test_closed_finding_requires_same_plan_validator() -> None:
    finding = ValidationFinding(
        finding_id="F-003",
        test_id="concept",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CLOSED,
        evidence_digest=D5,
        description="Finding retested and closed.",
        remediation_digest=D6,
        closed_by_validator_id="different-validator",
    )
    with pytest.raises(GovernanceError, match="plan validator"):
        resolve_validation(plan(), (finding,))


def test_validator_closed_findings_allow_pass() -> None:
    finding = ValidationFinding(
        finding_id="F-004",
        test_id="concept",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CLOSED,
        evidence_digest=D5,
        description="Finding remediated and independently retested.",
        remediation_digest=D6,
        closed_by_validator_id="independent-validator",
    )
    resolution = resolve_validation(plan(), (finding,))
    assert resolution.conclusion is ValidationConclusion.PASS
    assert resolution.open_finding_ids == ()


def test_finding_cannot_reference_test_outside_plan() -> None:
    finding = ValidationFinding(
        finding_id="F-005",
        test_id="unknown-test",
        severity=FindingSeverity.LOW,
        status=FindingStatus.OPEN,
        evidence_digest=D5,
        description="Unknown test reference.",
    )
    with pytest.raises(GovernanceError, match="outside the validation plan"):
        resolve_validation(plan(), (finding,))
