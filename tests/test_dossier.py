from dataclasses import replace
import json

import pytest

from modelriskops import (
    ApprovalDecision,
    DossierGovernanceState,
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
    assess_model_risk,
    build_governance_dossier,
    build_validation_plan,
    canonical_json,
    create_approval_vote,
    create_exception,
    default_policy,
    derive_approval_requirement,
    derive_revalidation_requirement,
    dossier_from_dict,
    resolve_approval,
    resolve_validation,
    verify_governance_dossier,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def approved_chain():
    record = ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="model-owner",
        business_use="Credit underwriting",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.VALIDATION,
        deployment_context="Internal underwriting service",
    )
    version = ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="2026.08.1",
        artifact_digest=D1,
        code_digest=D2,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
    )
    policy = default_policy("bank-a")
    factors = tuple(
        RiskFactor(factor=factor, level=FactorLevel.CRITICAL)
        for factor in FactorName
    )
    risk = assess_model_risk(record, version, factors, (), policy)
    plan = build_validation_plan(
        record,
        version,
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
    validation_resolution = resolve_validation(plan, ())
    requirement = derive_approval_requirement(
        record,
        version,
        risk,
        plan,
        validation_resolution,
    )
    votes = (
        create_approval_vote(
            record,
            requirement,
            approver_id="senior-risk-1",
            approver_role="senior_risk_approval",
            decision=ApprovalDecision.APPROVE,
        ),
        create_approval_vote(
            record,
            requirement,
            approver_id="executive-1",
            approver_role="executive_risk_acceptance",
            decision=ApprovalDecision.APPROVE,
        ),
    )
    approval_resolution = resolve_approval(requirement, votes)
    exception = create_exception(
        version,
        risk,
        exception_id="EX-1",
        waived_requirement_ids=("enhanced_monitoring",),
        owner_id="risk-owner",
        rationale="Temporary monitoring migration",
        compensating_controls=("daily-manual-review",),
        issued_at=100,
        expires_at=200,
    )
    return (
        record,
        version,
        policy,
        risk,
        plan,
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        exception,
    )


def build_approved_dossier():
    (
        record,
        version,
        policy,
        risk,
        plan,
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        exception,
    ) = approved_chain()
    return build_governance_dossier(
        record,
        version,
        policy,
        risk,
        plan,
        (),
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        exceptions=(exception,),
    )


def test_full_governance_journey_produces_deterministic_verified_dossier() -> None:
    first = build_approved_dossier()
    second = build_approved_dossier()
    assert first == second
    assert first.governance_state is DossierGovernanceState.APPROVED
    assert first.governance_path_complete is True
    assert first.manifest_digest == second.manifest_digest
    verify_governance_dossier(first)

    serialized = canonical_json(first)
    restored = dossier_from_dict(json.loads(serialized))
    assert restored == first
    assert restored.evidence_digest == first.evidence_digest


def test_dossier_rejects_validation_resolution_not_reproducible_from_findings() -> None:
    (
        record,
        version,
        policy,
        risk,
        plan,
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        _,
    ) = approved_chain()
    tampered_resolution = replace(
        validation_resolution,
        rationale="Different resolution rationale",
    )
    with pytest.raises(GovernanceError, match="does not reproduce"):
        build_governance_dossier(
            record,
            version,
            policy,
            risk,
            plan,
            (),
            tampered_resolution,
            requirement,
            votes,
            approval_resolution,
        )


def test_dossier_rejects_approval_resolution_not_reproducible_from_votes() -> None:
    (
        record,
        version,
        policy,
        risk,
        plan,
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        _,
    ) = approved_chain()
    tampered_approval = replace(approval_resolution, conditions=("invented-condition",))
    with pytest.raises(GovernanceError, match="does not reproduce"):
        build_governance_dossier(
            record,
            version,
            policy,
            risk,
            plan,
            (),
            validation_resolution,
            requirement,
            votes,
            tampered_approval,
        )


def test_artifact_payload_tamper_is_detected_offline() -> None:
    payload = json.loads(canonical_json(build_approved_dossier()))
    payload["entries"][0]["canonical_payload"] = "{}"
    with pytest.raises(GovernanceError):
        dossier_from_dict(payload)


def test_manifest_tamper_is_detected_offline() -> None:
    payload = json.loads(canonical_json(build_approved_dossier()))
    payload["manifest_digest"] = "0" * 64
    with pytest.raises(GovernanceError, match="manifest digest"):
        dossier_from_dict(payload)


def test_revalidation_requirement_prevents_complete_governance_path() -> None:
    (
        record,
        version,
        policy,
        risk,
        plan,
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        _,
    ) = approved_chain()
    revalidation = derive_revalidation_requirement(
        record,
        record,
        version,
        version,
        policy,
        policy,
        operational_triggers=(RevalidationTrigger.MONITORING_DETERIORATION,),
    )
    assert revalidation is not None
    dossier = build_governance_dossier(
        record,
        version,
        policy,
        risk,
        plan,
        (),
        validation_resolution,
        requirement,
        votes,
        approval_resolution,
        revalidation_requirement=revalidation,
    )
    assert dossier.governance_state is DossierGovernanceState.REVALIDATION_REQUIRED
    assert dossier.governance_path_complete is False
    assert dossier.gaps == ("revalidation_required",)
