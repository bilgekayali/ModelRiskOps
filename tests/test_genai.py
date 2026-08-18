from dataclasses import replace

import pytest

from modelriskops import (
    ChangeMateriality,
    DossierGovernanceState,
    FoundationModelDependency,
    GenAIEvaluationObservation,
    GenAIEvaluationState,
    GenAIMetricDefinition,
    GenAIMetricKind,
    GenAIRevalidationTrigger,
    GenAIUseCaseProfile,
    GovernanceError,
    HumanOversightDecisionKind,
    MetricDirection,
    PromptPolicyArtifact,
    RAGConfiguration,
    assess_genai_evaluation,
    assert_genai_change_proposal_current,
    build_genai_evaluation_plan,
    build_genai_governance_dossier,
    build_genai_overlay_snapshot,
    create_genai_model_change_proposal,
    create_human_oversight_decision,
    create_human_oversight_requirement,
    verify_governance_dossier,
)
from tests.test_dossier import approved_chain, build_approved_dossier


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64
D7 = "7" * 64
D8 = "8" * 64
D9 = "9" * 64


def overlay_fixture(*, prompt_digest: str = D2, corpus_digest: str = D4):
    record, version, policy, *_ = approved_chain()
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
        policy_version="1",
        owner_id="ai-risk-owner",
        intended_purpose="credit analyst assistance",
        prompt_digest=prompt_digest,
        safety_policy_digest=D3,
        prohibited_behaviors=("autonomous_credit_decision", "fabricated_source"),
        registered_at=101,
    )
    rag = RAGConfiguration(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        rag_id="credit-rag",
        config_version="1",
        owner_id="data-owner",
        corpus_id="approved-credit-policy",
        corpus_version="2026.08",
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
    overlay = build_genai_overlay_snapshot(foundation, prompt, use_case, rag)
    return record, version, policy, foundation, prompt, rag, use_case, overlay


def evaluation_fixture():
    record, version, policy, foundation, prompt, rag, use_case, overlay = overlay_fixture()
    metrics = (
        GenAIMetricDefinition(
            metric_id="factuality",
            kind=GenAIMetricKind.FACTUALITY,
            direction=MetricDirection.HIGHER_IS_BETTER,
            pass_threshold=0.90,
            warning_threshold=0.80,
            minimum_sample_size=20,
            max_age_seconds=100,
        ),
        GenAIMetricDefinition(
            metric_id="harmful-content",
            kind=GenAIMetricKind.HARMFUL_CONTENT,
            direction=MetricDirection.LOWER_IS_BETTER,
            pass_threshold=0.05,
            warning_threshold=0.10,
            minimum_sample_size=20,
            max_age_seconds=100,
        ),
    )
    plan = build_genai_evaluation_plan(
        record,
        version,
        overlay,
        evaluator_owner_id="independent-ai-validation",
        metrics=metrics,
        planned_at=110,
    )
    return record, version, policy, foundation, prompt, rag, use_case, overlay, plan


def observations(plan, *, factuality=0.95, harmful=0.02, observed_at=150, sample_size=100):
    return (
        GenAIEvaluationObservation(
            plan_digest=plan.evidence_digest,
            metric_id="factuality",
            value=factuality,
            observed_at=observed_at,
            sample_size=sample_size,
            source_evidence_digest=D1,
            evaluator_id="eval-runner",
        ),
        GenAIEvaluationObservation(
            plan_digest=plan.evidence_digest,
            metric_id="harmful-content",
            value=harmful,
            observed_at=observed_at,
            sample_size=sample_size,
            source_evidence_digest=D2,
            evaluator_id="eval-runner",
        ),
    )


def test_genai_evaluation_is_deterministic_and_fail_closed() -> None:
    *_, overlay, plan = evaluation_fixture()
    healthy = assess_genai_evaluation(plan, overlay, observations(plan), evaluated_at=160)
    assert healthy.state is GenAIEvaluationState.HEALTHY
    assert healthy.model_safety_determined is False
    assert healthy.regulatory_compliance_determined is False

    breached = assess_genai_evaluation(
        plan,
        overlay,
        observations(plan, factuality=0.60),
        evaluated_at=160,
    )
    assert breached.state is GenAIEvaluationState.BREACHED

    incomplete = assess_genai_evaluation(plan, overlay, observations(plan)[:1], evaluated_at=160)
    assert incomplete.state is GenAIEvaluationState.INCOMPLETE
    assert "missing_observation:harmful-content" in incomplete.gaps

    stale = assess_genai_evaluation(plan, overlay, observations(plan, observed_at=120), evaluated_at=230)
    assert stale.state is GenAIEvaluationState.INCOMPLETE

    conflict = observations(plan) + (
        replace(observations(plan)[0], value=0.10, source_evidence_digest=D3),
    )
    conflict_assessment = assess_genai_evaluation(plan, overlay, conflict, evaluated_at=160)
    assert conflict_assessment.state is GenAIEvaluationState.INCOMPLETE
    assert "conflicting_latest:factuality" in conflict_assessment.gaps


def test_human_oversight_cannot_weaken_explicit_use_case_requirement() -> None:
    *_, use_case, overlay, plan = evaluation_fixture()
    with pytest.raises(GovernanceError, match="cannot be weakened"):
        create_human_oversight_requirement(
            use_case,
            plan,
            required=False,
            rationale="attempt to waive review",
        )
    requirement = create_human_oversight_requirement(
        use_case,
        plan,
        required=True,
        required_roles=("human_reviewer",),
        rationale="high-impact use requires human review",
    )
    with pytest.raises(GovernanceError, match="reviewer role"):
        create_human_oversight_decision(
            requirement,
            reviewer_id="reviewer-1",
            reviewer_role="developer",
            decision=HumanOversightDecisionKind.ACCEPT,
            rationale="reviewed",
            evidence_digest=D4,
            decided_at=170,
        )


def test_genai_change_proposal_binds_exact_overlay_state() -> None:
    record, version, policy, *_, before_overlay = overlay_fixture(prompt_digest=D2)
    *_, after_overlay = overlay_fixture(prompt_digest=D8)
    proposal, revalidation, evidence = create_genai_model_change_proposal(
        record,
        record,
        version,
        version,
        policy,
        policy,
        before_overlay,
        after_overlay,
        change_id="GENAI-CHANGE-1",
        materiality=ChangeMateriality.MATERIAL,
        materiality_owner_id="ai-risk-owner",
        materiality_rationale="prompt policy change classified material by accountable owner",
        proposed_at=180,
        triggers=(GenAIRevalidationTrigger.PROMPT_POLICY, GenAIRevalidationTrigger.SAFETY_POLICY),
        revalidation_rationale="prompt/safety policy changed",
    )
    assert proposal.revalidation_requirement_digest == revalidation.evidence_digest
    assert evidence.after_overlay_digest == after_overlay.evidence_digest
    assert_genai_change_proposal_current(
        proposal,
        revalidation,
        evidence,
        record,
        record,
        version,
        version,
        policy,
        policy,
        before_overlay,
        after_overlay,
    )
    *_, substituted_overlay = overlay_fixture(prompt_digest=D7)
    with pytest.raises(GovernanceError, match="stale"):
        assert_genai_change_proposal_current(
            proposal,
            revalidation,
            evidence,
            record,
            record,
            version,
            version,
            policy,
            policy,
            before_overlay,
            substituted_overlay,
        )


def test_genai_dossier_propagates_evaluation_and_oversight_state() -> None:
    record, version, policy, foundation, prompt, rag, use_case, overlay, plan = evaluation_fixture()
    base = build_approved_dossier()
    healthy = assess_genai_evaluation(plan, overlay, observations(plan), evaluated_at=160)
    requirement = create_human_oversight_requirement(
        use_case,
        plan,
        required=True,
        required_roles=("human_reviewer",),
        rationale="review required",
    )
    accepted = create_human_oversight_decision(
        requirement,
        reviewer_id="reviewer-1",
        reviewer_role="human_reviewer",
        decision=HumanOversightDecisionKind.ACCEPT,
        rationale="review accepted for represented evidence",
        evidence_digest=D5,
        decided_at=170,
    )
    dossier = build_genai_governance_dossier(
        base, foundation, prompt, use_case, overlay, plan, healthy,
        rag=rag, oversight_requirement=requirement, oversight_decision=accepted,
    )
    verify_governance_dossier(dossier)
    assert dossier.governance_path_complete is True

    breached = assess_genai_evaluation(plan, overlay, observations(plan, factuality=0.50), evaluated_at=160)
    blocked = build_genai_governance_dossier(
        base, foundation, prompt, use_case, overlay, plan, breached,
        rag=rag, oversight_requirement=requirement, oversight_decision=accepted,
    )
    assert blocked.governance_state is DossierGovernanceState.REVALIDATION_REQUIRED
    assert blocked.governance_path_complete is False
    assert "genai_evaluation_breached" in blocked.gaps

    escalated = create_human_oversight_decision(
        requirement,
        reviewer_id="reviewer-1",
        reviewer_role="human_reviewer",
        decision=HumanOversightDecisionKind.ESCALATE,
        rationale="requires risk escalation",
        evidence_digest=D6,
        decided_at=171,
    )
    escalated_dossier = build_genai_governance_dossier(
        base, foundation, prompt, use_case, overlay, plan, healthy,
        rag=rag, oversight_requirement=requirement, oversight_decision=escalated,
    )
    assert escalated_dossier.governance_state is DossierGovernanceState.REVALIDATION_REQUIRED
    assert "human_oversight_escalated" in escalated_dossier.gaps
