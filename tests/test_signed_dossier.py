from dataclasses import replace

import pytest

from modelriskops import (
    ApprovalDecision,
    GovernanceError,
    build_governance_dossier,
    build_signed_change_dossier,
    canonical_json,
    create_approval_vote,
    create_change_implementation_evidence,
    dossier_from_dict,
    resolve_change_authorization,
    verify_governance_dossier,
)
from tests.test_change_control import material_change_package


def build_signed_dossier_fixture():
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
    base = build_governance_dossier(
        after_record,
        after_version,
        policy,
        risk,
        plan,
        (),
        validation_resolution,
        approval_requirement,
        approval_votes,
        approval_resolution,
    )
    authorization = resolve_change_authorization(
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
    implementation = create_change_implementation_evidence(
        proposal,
        authorization,
        after_record,
        after_version,
        policy,
        implemented_by_id="release-engineer",
        implementation_evidence_digest="9" * 64,
        implemented_at=180,
    )
    signed = build_signed_change_dossier(
        base,
        proposal,
        requirement,
        votes,
        signatures,
        authorization,
        registry,
        implementation=implementation,
    )
    return signed, base, proposal, requirement, votes, signatures, authorization, registry, implementation


def test_signed_change_dossier_is_deterministic_and_offline_verifiable() -> None:
    signed, base, *_ = build_signed_dossier_fixture()
    verify_governance_dossier(signed)
    assert signed.manifest_digest != base.manifest_digest
    artifact_types = {entry.artifact_type for entry in signed.entries}
    assert {
        "model_change_proposal",
        "change_authorization_requirement",
        "change_authorization_vote",
        "signed_change_authorization_vote",
        "change_authorization_resolution",
        "change_implementation",
    }.issubset(artifact_types)
    restored = dossier_from_dict(__import__("json").loads(canonical_json(signed)))
    assert restored == signed


def test_signed_change_dossier_rejects_signature_set_substitution() -> None:
    signed, base, proposal, requirement, votes, signatures, authorization, registry, implementation = build_signed_dossier_fixture()
    assert signed is not None
    swapped = {
        votes[0].evidence_digest: signatures[votes[1].evidence_digest],
        votes[1].evidence_digest: signatures[votes[0].evidence_digest],
    }
    with pytest.raises(GovernanceError):
        build_signed_change_dossier(
            base,
            proposal,
            requirement,
            votes,
            swapped,
            authorization,
            registry,
            implementation=implementation,
        )


def test_signed_change_dossier_rejects_implementation_for_wrong_authorization() -> None:
    _, base, proposal, requirement, votes, signatures, authorization, registry, implementation = build_signed_dossier_fixture()
    bad = replace(implementation, authorization_resolution_digest="a" * 64)
    with pytest.raises(GovernanceError, match="different authorization"):
        build_signed_change_dossier(
            base,
            proposal,
            requirement,
            votes,
            signatures,
            authorization,
            registry,
            implementation=bad,
        )


def test_after_state_signed_dossier_rejects_incomplete_change_authorization() -> None:
    _, base, proposal, requirement, votes, signatures, _, registry, _ = build_signed_dossier_fixture()
    incomplete = resolve_change_authorization(
        proposal,
        requirement,
        votes[:1],
        {votes[0].evidence_digest: signatures[votes[0].evidence_digest]},
        registry,
        resolved_at=170,
    )
    with pytest.raises(GovernanceError, match="requires authorized change"):
        build_signed_change_dossier(
            base,
            proposal,
            requirement,
            votes[:1],
            {votes[0].evidence_digest: signatures[votes[0].evidence_digest]},
            incomplete,
            registry,
        )
