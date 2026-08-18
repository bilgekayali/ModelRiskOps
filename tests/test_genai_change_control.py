import pytest

from modelriskops import (
    ChangeAuthorizationDecision,
    ChangeMateriality,
    FoundationModelDependency,
    GenAIRevalidationTrigger,
    GenAIUseCaseProfile,
    GovernanceError,
    PromptPolicyArtifact,
    RAGConfiguration,
    assert_genai_change_implementation_current,
    build_genai_overlay_snapshot,
    create_change_authorization_vote,
    create_change_implementation_evidence,
    create_genai_change_implementation_evidence,
    create_genai_model_change_proposal,
    create_signed_envelope,
    derive_change_authorization_requirement,
    resolve_change_authorization,
)
from tests.test_change_control import (
    SEED_CHANGE,
    SEED_RISK,
    after_governance_chain,
    signing_fixture,
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


def overlay_for(record, version, *, prompt_digest: str, corpus_digest: str):
    foundation = FoundationModelDependency(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        provider="provider-a",
        provider_model_id="foundation-x",
        provider_model_version="2026-08",
        deployment_id="private-endpoint-1",
        owner_id="ai-platform-owner",
        artifact_digest=D1,
        config_digest=D2,
        terms_evidence_digest=D3,
        registered_at=100,
    )
    prompt = PromptPolicyArtifact(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        prompt_policy_id="system-policy",
        policy_version=version.version_id,
        owner_id="ai-risk-owner",
        intended_purpose="credit analyst assistance",
        prompt_digest=prompt_digest,
        safety_policy_digest=D3,
        prohibited_behaviors=("autonomous_credit_decision",),
        registered_at=101,
    )
    rag = RAGConfiguration(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        rag_id="credit-rag",
        config_version=version.version_id,
        owner_id="data-owner",
        corpus_id="approved-credit-policy",
        corpus_version=version.version_id,
        corpus_digest=corpus_digest,
        index_digest=D5,
        embedding_model_id="embed-x",
        embedding_model_version="2",
        embedding_model_digest=D6,
        chunking_policy_digest=D7,
        retrieval_policy_digest=D8,
        source_set_digest=D9,
        require_citations=True,
        registered_at=102,
    )
    use_case = GenAIUseCaseProfile(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        use_case_id="credit-analyst-copilot",
        owner_id="business-owner",
        intended_users=("credit_analyst",),
        prohibited_uses=("final_credit_decision",),
        output_handling="human review before downstream use",
        human_review_required=True,
        high_impact_use=True,
        permitted_tool_actions=("retrieve_policy",),
        registered_at=103,
    )
    return build_genai_overlay_snapshot(foundation, prompt, use_case, rag)


def test_genai_signed_change_authorization_and_overlay_aware_implementation() -> None:
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
    before_overlay = overlay_for(before_record, before_version, prompt_digest=D2, corpus_digest=D4)
    after_overlay = overlay_for(after_record, after_version, prompt_digest=D8, corpus_digest=D9)
    proposal, revalidation, genai_evidence = create_genai_model_change_proposal(
        before_record,
        after_record,
        before_version,
        after_version,
        policy,
        policy,
        before_overlay,
        after_overlay,
        change_id="GENAI-CHG-2",
        materiality=ChangeMateriality.MATERIAL,
        materiality_owner_id="ai-risk-owner",
        materiality_rationale="accountable materiality decision for prompt/retrieval change",
        proposed_at=120,
        triggers=(GenAIRevalidationTrigger.PROMPT_POLICY, GenAIRevalidationTrigger.RETRIEVAL_CORPUS),
        revalidation_rationale="prompt and governed retrieval corpus changed",
    )
    requirement = derive_change_authorization_requirement(proposal)
    votes = (
        create_change_authorization_vote(
            proposal, requirement,
            approver_id="change-risk-approver", approver_role="model_risk_approver",
            decision=ChangeAuthorizationDecision.AUTHORIZE,
            rationale="independent risk authorization", decided_at=150,
        ),
        create_change_authorization_vote(
            proposal, requirement,
            approver_id="change-control-approver", approver_role="change_control_approver",
            decision=ChangeAuthorizationDecision.AUTHORIZE,
            rationale="change-control authorization", decided_at=151,
        ),
    )
    registry, risk_key, change_key = signing_fixture()
    signatures = {
        votes[0].evidence_digest: create_signed_envelope(
            votes[0], registry, risk_key, private_key_seed=SEED_RISK,
            institution_id=proposal.institution_id, model_id=proposal.model_id,
            version_id=proposal.after_version_id, artifact_type="model_change_authorization_vote",
            signer_id=votes[0].approver_id, signer_role=votes[0].approver_role,
            signing_purpose="authorize_model_change", signed_at=160,
        ),
        votes[1].evidence_digest: create_signed_envelope(
            votes[1], registry, change_key, private_key_seed=SEED_CHANGE,
            institution_id=proposal.institution_id, model_id=proposal.model_id,
            version_id=proposal.after_version_id, artifact_type="model_change_authorization_vote",
            signer_id=votes[1].approver_id, signer_role=votes[1].approver_role,
            signing_purpose="authorize_model_change", signed_at=161,
        ),
    }
    authorization = resolve_change_authorization(
        proposal, requirement, votes, signatures, registry,
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

    with pytest.raises(GovernanceError, match="governance state differs"):
        create_change_implementation_evidence(
            proposal, authorization, after_record, after_version, policy,
            implemented_by_id="release-engineer",
            implementation_evidence_digest=D7,
            implemented_at=180,
        )

    implementation = create_genai_change_implementation_evidence(
        proposal,
        authorization,
        genai_evidence,
        after_record,
        after_version,
        policy,
        after_overlay,
        implemented_by_id="release-engineer",
        implementation_evidence_digest=D7,
        implemented_at=180,
    )
    assert implementation.authorized_after_state_digest == proposal.after_state_digest
    assert_genai_change_implementation_current(
        implementation,
        proposal,
        authorization,
        genai_evidence,
        after_record,
        after_version,
        policy,
        after_overlay,
    )

    substituted_overlay = overlay_for(after_record, after_version, prompt_digest=D6, corpus_digest=D9)
    with pytest.raises(GovernanceError, match="authorized overlay"):
        create_genai_change_implementation_evidence(
            proposal,
            authorization,
            genai_evidence,
            after_record,
            after_version,
            policy,
            substituted_overlay,
            implemented_by_id="release-engineer",
            implementation_evidence_digest=D7,
            implemented_at=180,
        )
