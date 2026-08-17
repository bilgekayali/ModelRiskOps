from dataclasses import replace

import pytest

from modelriskops import (
    ApprovalDecision,
    ApprovalState,
    FactorLevel,
    FactorName,
    GovernanceError,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    RevalidationTrigger,
    RiskFactor,
    TestStatus,
    ValidationDomain,
    ValidationTest,
    assert_approval_requirement_current,
    assert_exception_valid,
    assess_model_risk,
    build_validation_plan,
    create_approval_vote,
    create_exception,
    default_policy,
    derive_approval_requirement,
    derive_revalidation_requirement,
    resolve_approval,
    resolve_validation,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def record(*, business_use: str = "Credit underwriting") -> ModelRecord:
    return ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="model-owner",
        business_use=business_use,
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.VALIDATION,
        deployment_context="Internal underwriting service",
    )


def version(*, code_digest: str = D2) -> ModelVersion:
    return ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="2026.08.1",
        artifact_digest=D1,
        code_digest=code_digest,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
    )


def governance_chain():
    current_record = record()
    current_version = version()
    factors = tuple(
        RiskFactor(factor=factor, level=FactorLevel.CRITICAL)
        for factor in FactorName
    )
    risk = assess_model_risk(
        current_record,
        current_version,
        factors,
        (),
        default_policy("bank-a"),
    )
    plan = build_validation_plan(
        current_record,
        current_version,
        risk,
        validator_id="validator-1",
        validator_role="model-validation",
        independent_from_owner=True,
        tests=(
            ValidationTest(
                test_id="concept",
                domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
                mandatory=True,
                status=TestStatus.PASS,
                evidence_digest=D5,
            ),
        ),
    )
    resolution = resolve_validation(plan, ())
    requirement = derive_approval_requirement(
        current_record,
        current_version,
        risk,
        plan,
        resolution,
    )
    return current_record, current_version, risk, plan, resolution, requirement


def test_critical_risk_requires_two_distinct_approval_roles() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    assert requirement.required_roles == (
        "senior_risk_approval",
        "executive_risk_acceptance",
    )
    senior = create_approval_vote(
        current_record,
        requirement,
        approver_id="senior-risk-1",
        approver_role="senior_risk_approval",
        decision=ApprovalDecision.APPROVE,
    )
    executive = create_approval_vote(
        current_record,
        requirement,
        approver_id="executive-1",
        approver_role="executive_risk_acceptance",
        decision=ApprovalDecision.APPROVE,
    )
    resolved = resolve_approval(requirement, (executive, senior))
    assert resolved.state is ApprovalState.APPROVED
    assert resolved.missing_roles == ()


def test_same_person_cannot_fill_two_required_approval_roles() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    senior = create_approval_vote(
        current_record,
        requirement,
        approver_id="same-person",
        approver_role="senior_risk_approval",
        decision=ApprovalDecision.APPROVE,
    )
    executive = create_approval_vote(
        current_record,
        requirement,
        approver_id="same-person",
        approver_role="executive_risk_acceptance",
        decision=ApprovalDecision.APPROVE,
    )
    with pytest.raises(GovernanceError, match="distinct people"):
        resolve_approval(requirement, (senior, executive))


def test_model_owner_cannot_self_approve() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    with pytest.raises(GovernanceError, match="cannot approve"):
        create_approval_vote(
            current_record,
            requirement,
            approver_id="model-owner",
            approver_role="senior_risk_approval",
            decision=ApprovalDecision.APPROVE,
        )


def test_missing_required_role_keeps_approval_incomplete() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    senior = create_approval_vote(
        current_record,
        requirement,
        approver_id="senior-risk-1",
        approver_role="senior_risk_approval",
        decision=ApprovalDecision.APPROVE,
    )
    resolved = resolve_approval(requirement, (senior,))
    assert resolved.state is ApprovalState.INCOMPLETE
    assert resolved.missing_roles == ("executive_risk_acceptance",)


def test_reject_vote_is_terminal_for_resolution() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    rejected = create_approval_vote(
        current_record,
        requirement,
        approver_id="senior-risk-1",
        approver_role="senior_risk_approval",
        decision=ApprovalDecision.REJECT,
    )
    resolved = resolve_approval(requirement, (rejected,))
    assert resolved.state is ApprovalState.REJECTED


def test_conditional_approval_preserves_conditions() -> None:
    current_record, _, _, _, _, requirement = governance_chain()
    senior = create_approval_vote(
        current_record,
        requirement,
        approver_id="senior-risk-1",
        approver_role="senior_risk_approval",
        decision=ApprovalDecision.APPROVE_WITH_CONDITIONS,
        conditions=("weekly-monitoring",),
    )
    executive = create_approval_vote(
        current_record,
        requirement,
        approver_id="executive-1",
        approver_role="executive_risk_acceptance",
        decision=ApprovalDecision.APPROVE,
    )
    resolved = resolve_approval(requirement, (senior, executive))
    assert resolved.state is ApprovalState.APPROVED_WITH_CONDITIONS
    assert resolved.conditions == ("weekly-monitoring",)


def test_exception_scope_expiry_and_one_time_semantics_fail_closed() -> None:
    _, current_version, risk, _, _, _ = governance_chain()
    exception = create_exception(
        current_version,
        risk,
        exception_id="EX-1",
        waived_requirement_ids=("enhanced_monitoring",),
        owner_id="risk-owner",
        rationale="Temporary migration control gap",
        compensating_controls=("daily-manual-review",),
        issued_at=100,
        expires_at=200,
        one_time=True,
    )
    assert_exception_valid(
        exception,
        current_version,
        risk,
        "enhanced_monitoring",
        at_time=150,
    )
    with pytest.raises(GovernanceError, match="outside exception scope"):
        assert_exception_valid(exception, current_version, risk, "change_control", at_time=150)
    with pytest.raises(GovernanceError, match="not currently valid"):
        assert_exception_valid(exception, current_version, risk, "enhanced_monitoring", at_time=200)
    with pytest.raises(GovernanceError, match="already been consumed"):
        assert_exception_valid(
            exception,
            current_version,
            risk,
            "enhanced_monitoring",
            at_time=150,
            consumed=True,
        )


def test_exception_cannot_waive_independent_validation() -> None:
    _, current_version, risk, _, _, _ = governance_chain()
    with pytest.raises(GovernanceError, match="non-exceptionable"):
        create_exception(
            current_version,
            risk,
            exception_id="EX-2",
            waived_requirement_ids=("independent_validation",),
            owner_id="risk-owner",
            rationale="Not permitted",
            compensating_controls=("manual-review",),
            issued_at=100,
            expires_at=200,
        )


def test_approval_requirement_is_bound_to_exact_current_chain() -> None:
    current_record, current_version, risk, plan, resolution, requirement = governance_chain()
    assert_approval_requirement_current(
        requirement,
        current_record,
        current_version,
        risk,
        plan,
        resolution,
    )
    with pytest.raises(GovernanceError, match="stale for model version"):
        assert_approval_requirement_current(
            requirement,
            current_record,
            version(code_digest="a" * 64),
            risk,
            plan,
            resolution,
        )


def test_material_changes_produce_deterministic_revalidation_requirement() -> None:
    before_record = record()
    after_record = record(business_use="Credit underwriting and pricing")
    before_version = version()
    after_version = version(code_digest="a" * 64)
    before_policy = default_policy("bank-a")
    after_policy = replace(before_policy, version="2")

    first = derive_revalidation_requirement(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
    )
    second = derive_revalidation_requirement(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
    )
    assert first is not None
    assert first == second
    assert RevalidationTrigger.BUSINESS_USE in first.triggers
    assert RevalidationTrigger.CODE in first.triggers
    assert RevalidationTrigger.POLICY_PROFILE in first.triggers


def test_operational_deterioration_alone_triggers_revalidation() -> None:
    current_record = record()
    current_version = version()
    current_policy = default_policy("bank-a")
    requirement = derive_revalidation_requirement(
        current_record,
        current_record,
        current_version,
        current_version,
        current_policy,
        current_policy,
        operational_triggers=(RevalidationTrigger.MONITORING_DETERIORATION,),
    )
    assert requirement is not None
    assert requirement.triggers == (RevalidationTrigger.MONITORING_DETERIORATION,)
    assert requirement.before_state_digest != requirement.after_state_digest


def test_unchanged_state_does_not_require_revalidation() -> None:
    current_record = record()
    current_version = version()
    current_policy = default_policy("bank-a")
    assert derive_revalidation_requirement(
        current_record,
        current_record,
        current_version,
        current_version,
        current_policy,
        current_policy,
    ) is None
