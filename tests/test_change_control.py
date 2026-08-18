from dataclasses import replace

import pytest

from modelriskops import (
    ApprovalDecision,
    ChangeAuthorizationDecision,
    ChangeAuthorizationState,
    ChangeMateriality,
    FactorLevel,
    FactorName,
    GovernanceError,
    KeyRevocation,
    RiskFactor,
    SigningKeyRegistry,
    TestStatus,
    ValidationDomain,
    ValidationTest,
    VerificationKeyRecord,
    assess_model_risk,
    assert_change_implementation_current,
    build_validation_plan,
    create_approval_vote,
    create_change_authorization_vote,
    create_change_implementation_evidence,
    create_model_change_proposal,
    create_signed_envelope,
    derive_approval_requirement,
    derive_change_authorization_requirement,
    derive_revalidation_requirement,
    public_key_base64_from_private_seed,
    resolve_approval,
    resolve_change_authorization,
    resolve_validation,
)
from tests.test_dossier import D1, D2, D3, D4, D5, approved_chain


SEED_RISK = b"r" * 32
SEED_CHANGE = b"c" * 32


def after_governance_chain():
    before_record, before_version, policy, *_ = approved_chain()
    after_record = before_record
    after_version = replace(
        before_version,
        version_id="2026.09.1",
        artifact_digest="6" * 64,
        code_digest="7" * 64,
    )
    factors = tuple(RiskFactor(factor=factor, level=FactorLevel.CRITICAL) for factor in FactorName)
    risk = assess_model_risk(after_record, after_version, factors, (), policy)
    plan = build_validation_plan(
        after_record,
        after_version,
        risk,
        validator_id="validator-2",
        validator_role="model-validation",
        independent_from_owner=True,
        tests=(
            ValidationTest(
                test_id="concept-v2",
                domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
                mandatory=True,
                status=TestStatus.PASS,
                evidence_digest="8" * 64,
            ),
        ),
    )
    validation_resolution = resolve_validation(plan, ())
    approval_requirement = derive_approval_requirement(
        after_record,
        after_version,
        risk,
        plan,
        validation_resolution,
    )
    approval_votes = (
        create_approval_vote(
            after_record,
            approval_requirement,
            approver_id="senior-risk-2",
            approver_role="senior_risk_approval",
            decision=ApprovalDecision.APPROVE,
        ),
        create_approval_vote(
            after_record,
            approval_requirement,
            approver_id="executive-2",
            approver_role="executive_risk_acceptance",
            decision=ApprovalDecision.APPROVE,
        ),
    )
    approval_resolution = resolve_approval(approval_requirement, approval_votes)
    return (
        before_record,
        before_version,
        policy,
        after_record,
        after_version,
        risk,
        plan,
        validation_resolution,
        approval_requirement,
        approval_resolution,
    )


def signing_fixture():
    registry = SigningKeyRegistry()
    risk_key = VerificationKeyRecord(
        institution_id="bank-a",
        key_id="risk-key",
        owner_id="change-risk-approver",
        public_key_base64=public_key_base64_from_private_seed(SEED_RISK),
        permitted_roles=("model_risk_approver",),
        valid_from=100,
        valid_until=1000,
        registered_at=90,
    )
    change_key = VerificationKeyRecord(
        institution_id="bank-a",
        key_id="change-key",
        owner_id="change-control-approver",
        public_key_base64=public_key_base64_from_private_seed(SEED_CHANGE),
        permitted_roles=("change_control_approver",),
        valid_from=100,
        valid_until=1000,
        registered_at=90,
    )
    registry.register_key(risk_key)
    registry.register_key(change_key)
    return registry, risk_key, change_key


def material_change_package():
    (
        before_record,
        before_version,
        policy,
        after_record,
        after_version,
        risk,
        plan,
        validation_resolution,
        approval_requirement,
        approval_resolution,
    ) = after_governance_chain()
    proposal = create_model_change_proposal(
        before_record,
        after_record,
        before_version,
        after_version,
        policy,
        policy,
        change_id="CHG-1",
        materiality=ChangeMateriality.MATERIAL,
        materiality_owner_id="model-owner",
        materiality_rationale="New model artifact and code require governed material change approval.",
        proposed_at=120,
    )
    revalidation = derive_revalidation_requirement(
        before_record,
        after_record,
        before_version,
        after_version,
        policy,
        policy,
    )
    assert revalidation is not None
    requirement = derive_change_authorization_requirement(proposal)
    votes = (
        create_change_authorization_vote(
            proposal,
            requirement,
            approver_id="change-risk-approver",
            approver_role="model_risk_approver",
            decision=ChangeAuthorizationDecision.AUTHORIZE,
            rationale="Independent model risk authorization.",
            decided_at=150,
        ),
        create_change_authorization_vote(
            proposal,
            requirement,
            approver_id="change-control-approver",
            approver_role="change_control_approver",
            decision=ChangeAuthorizationDecision.AUTHORIZE,
            rationale="Change-control authorization for exact after state.",
            decided_at=151,
        ),
    )
    registry, risk_key, change_key = signing_fixture()
    signatures = {
        votes[0].evidence_digest: create_signed_envelope(
            votes[0],
            registry,
            risk_key,
            private_key_seed=SEED_RISK,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id=after_version.version_id,
            artifact_type="model_change_authorization_vote",
            signer_id=votes[0].approver_id,
            signer_role=votes[0].approver_role,
            signing_purpose="authorize_model_change",
            signed_at=160,
        ),
        votes[1].evidence_digest: create_signed_envelope(
            votes[1],
            registry,
            change_key,
            private_key_seed=SEED_CHANGE,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id=after_version.version_id,
            artifact_type="model_change_authorization_vote",
            signer_id=votes[1].approver_id,
            signer_role=votes[1].approver_role,
            signing_purpose="authorize_model_change",
            signed_at=161,
        ),
    }
    return (
        proposal,
        requirement,
        votes,
        signatures,
        registry,
        revalidation,
        after_record,
        after_version,
        policy,
        risk,
        plan,
        validation_resolution,
        approval_requirement,
        approval_resolution,
    )


def test_material_change_requires_signed_independent_votes_and_current_approval_chain() -> None:
    (
        proposal,
        requirement,
        votes,
        signatures,
        registry,
        revalidation,
        after_record,
        after_version,
        policy,
        risk,
        plan,
        validation_resolution,
        approval_requirement,
        approval_resolution,
    ) = material_change_package()

    resolution = resolve_change_authorization(
        proposal,
        requirement,
        votes,
        signatures,
        registry,
        resolved_at=170,
        revalidation_requirement=revalidation,
        after_record=after_record,
        after_version=after_version,
        after_risk=risk,
        validation_plan=plan,
        validation_resolution=validation_resolution,
        approval_requirement=approval_requirement,
        approval_resolution=approval_resolution,
    )
    assert resolution.state is ChangeAuthorizationState.AUTHORIZED
    assert len(resolution.vote_digests) == 2
    assert len(resolution.signature_digests) == 2
    assert resolution.approval_requirement_digest == approval_requirement.evidence_digest
    assert resolution.approval_resolution_digest == approval_resolution.evidence_digest
    assert resolution.automated_deployment_authorized is False
    assert resolution.regulatory_approval_determined is False

    implementation = create_change_implementation_evidence(
        proposal,
        resolution,
        after_record,
        after_version,
        policy,
        implemented_by_id="release-engineer",
        implementation_evidence_digest="9" * 64,
        implemented_at=180,
    )
    assert implementation.deployment_executed_by_modelriskops is False
    assert_change_implementation_current(
        implementation,
        proposal,
        resolution,
        after_record,
        after_version,
        policy,
    )


def test_missing_authorization_role_is_incomplete_not_authorized() -> None:
    package = material_change_package()
    proposal, requirement, votes, signatures, registry = package[:5]
    resolution = resolve_change_authorization(
        proposal,
        requirement,
        votes[:1],
        {votes[0].evidence_digest: signatures[votes[0].evidence_digest]},
        registry,
        resolved_at=170,
    )
    assert resolution.state is ChangeAuthorizationState.INCOMPLETE
    assert resolution.missing_roles == ("change_control_approver",)


def test_material_change_cannot_authorize_without_revalidation_or_current_approval() -> None:
    package = material_change_package()
    proposal, requirement, votes, signatures, registry = package[:5]
    with pytest.raises(GovernanceError, match="revalidation"):
        resolve_change_authorization(
            proposal,
            requirement,
            votes,
            signatures,
            registry,
            resolved_at=170,
        )

    revalidation = package[5]
    with pytest.raises(GovernanceError, match="complete current after-state approval"):
        resolve_change_authorization(
            proposal,
            requirement,
            votes,
            signatures,
            registry,
            resolved_at=170,
            revalidation_requirement=revalidation,
        )


def test_revoked_signing_key_blocks_current_change_authorization() -> None:
    package = material_change_package()
    proposal, requirement, votes, signatures, registry = package[:5]
    risk_envelope = signatures[votes[0].evidence_digest]
    risk_key = registry.key("bank-a", risk_envelope.key_id)
    registry.revoke_key(
        KeyRevocation(
            institution_id="bank-a",
            key_id=risk_key.key_id,
            key_digest=risk_key.evidence_digest,
            revoked_by_id="security-admin",
            reason="credential compromise",
            revoked_at=165,
        )
    )
    with pytest.raises(GovernanceError, match="revoked"):
        resolve_change_authorization(
            proposal,
            requirement,
            votes,
            signatures,
            registry,
            resolved_at=170,
        )


def test_materiality_owner_cannot_self_authorize_and_implementation_is_exact_state_bound() -> None:
    package = material_change_package()
    proposal, requirement = package[:2]
    with pytest.raises(GovernanceError, match="materiality decision owner"):
        create_change_authorization_vote(
            proposal,
            requirement,
            approver_id=proposal.materiality_owner_id,
            approver_role="model_risk_approver",
            decision=ChangeAuthorizationDecision.AUTHORIZE,
            rationale="self approval",
            decided_at=150,
        )

    (
        _,
        _,
        votes,
        signatures,
        registry,
        revalidation,
        after_record,
        after_version,
        policy,
        risk,
        plan,
        validation_resolution,
        approval_requirement,
        approval_resolution,
    ) = package
    resolution = resolve_change_authorization(
        proposal,
        requirement,
        votes,
        signatures,
        registry,
        resolved_at=170,
        revalidation_requirement=revalidation,
        after_record=after_record,
        after_version=after_version,
        after_risk=risk,
        validation_plan=plan,
        validation_resolution=validation_resolution,
        approval_requirement=approval_requirement,
        approval_resolution=approval_resolution,
    )
    with pytest.raises(GovernanceError, match="model version differs"):
        create_change_implementation_evidence(
            proposal,
            resolution,
            after_record,
            replace(after_version, code_digest="a" * 64),
            policy,
            implemented_by_id="release-engineer",
            implementation_evidence_digest="9" * 64,
            implemented_at=180,
        )


def test_non_material_change_remains_explicit_and_still_requires_signed_change_control_vote() -> None:
    before_record, before_version, policy, *_ = approved_chain()
    after_record = replace(before_record, deployment_context="Same service, updated non-functional routing metadata")
    proposal = create_model_change_proposal(
        before_record,
        after_record,
        before_version,
        before_version,
        policy,
        policy,
        change_id="CHG-2",
        materiality=ChangeMateriality.NON_MATERIAL,
        materiality_owner_id="model-owner",
        materiality_rationale="Institutional decision: no model behavior or artifact change.",
        proposed_at=120,
    )
    requirement = derive_change_authorization_requirement(proposal)
    assert requirement.required_roles == ("change_control_approver",)
    vote = create_change_authorization_vote(
        proposal,
        requirement,
        approver_id="change-control-approver",
        approver_role="change_control_approver",
        decision=ChangeAuthorizationDecision.AUTHORIZE,
        rationale="Non-material change independently reviewed.",
        decided_at=150,
    )
    registry, _, change_key = signing_fixture()
    envelope = create_signed_envelope(
        vote,
        registry,
        change_key,
        private_key_seed=SEED_CHANGE,
        institution_id="bank-a",
        model_id="credit-risk",
        version_id=before_version.version_id,
        artifact_type="model_change_authorization_vote",
        signer_id=vote.approver_id,
        signer_role=vote.approver_role,
        signing_purpose="authorize_model_change",
        signed_at=160,
    )
    resolution = resolve_change_authorization(
        proposal,
        requirement,
        (vote,),
        {vote.evidence_digest: envelope},
        registry,
        resolved_at=170,
    )
    assert resolution.state is ChangeAuthorizationState.AUTHORIZED
    assert resolution.approval_requirement_digest is None
