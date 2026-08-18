from __future__ import annotations

import json

from .canonical import canonical_json, sha256_digest
from .dossier import DossierEntry, DossierGovernanceState, GovernanceDossier, verify_governance_dossier
from .genai import (
    FoundationModelDependency,
    GenAIEvaluationAssessment,
    GenAIEvaluationPlan,
    GenAIEvaluationState,
    GenAIOverlaySnapshot,
    GenAIRevalidationEvidence,
    GenAIUseCaseProfile,
    HumanOversightDecision,
    HumanOversightDecisionKind,
    HumanOversightRequirement,
    PromptPolicyArtifact,
    RAGConfiguration,
)
from .models import GovernanceError


def _entry(artifact_type: str, artifact_id: str, artifact) -> DossierEntry:
    payload = canonical_json(artifact)
    return DossierEntry(
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        digest=sha256_digest(json.loads(payload)),
        canonical_payload=payload,
    )


def _manifest(
    dossier: GovernanceDossier,
    entries: tuple[DossierEntry, ...],
    *,
    governance_state: DossierGovernanceState,
    governance_path_complete: bool,
    conditions: tuple[str, ...],
    gaps: tuple[str, ...],
) -> str:
    return sha256_digest(
        {
            "institution_id": dossier.institution_id,
            "model_id": dossier.model_id,
            "version_id": dossier.version_id,
            "governance_state": governance_state.value,
            "governance_path_complete": governance_path_complete,
            "conditions": list(conditions),
            "gaps": list(gaps),
            "artifacts": [
                {
                    "artifact_type": entry.artifact_type,
                    "artifact_id": entry.artifact_id,
                    "digest": entry.digest,
                }
                for entry in entries
            ],
        }
    )


def build_genai_governance_dossier(
    base_dossier: GovernanceDossier,
    foundation: FoundationModelDependency,
    prompt_policy: PromptPolicyArtifact,
    use_case: GenAIUseCaseProfile,
    overlay: GenAIOverlaySnapshot,
    evaluation_plan: GenAIEvaluationPlan,
    evaluation_assessment: GenAIEvaluationAssessment,
    *,
    rag: RAGConfiguration | None = None,
    oversight_requirement: HumanOversightRequirement | None = None,
    oversight_decision: HumanOversightDecision | None = None,
    revalidation_evidence: GenAIRevalidationEvidence | None = None,
) -> GovernanceDossier:
    """Append typed GenAI evidence and fail closed on represented deterioration.

    Evaluation and oversight evidence affects governance completeness, but never becomes
    an automatic safety, compliance or deployment conclusion.
    """
    verify_governance_dossier(base_dossier)
    expected_scope = (base_dossier.institution_id, base_dossier.model_id, base_dossier.version_id)
    artifacts = [foundation, prompt_policy, use_case]
    if rag is not None:
        artifacts.append(rag)
    for artifact in artifacts:
        if (artifact.institution_id, artifact.model_id, artifact.version_id) != expected_scope:
            raise GovernanceError("GenAI dossier artifact is outside exact dossier scope")

    if (overlay.institution_id, overlay.model_id, overlay.version_id) != expected_scope:
        raise GovernanceError("GenAI overlay is outside exact dossier scope")
    if overlay.foundation_model_digest != foundation.evidence_digest:
        raise GovernanceError("GenAI overlay foundation-model binding is stale")
    if overlay.prompt_policy_digest != prompt_policy.evidence_digest:
        raise GovernanceError("GenAI overlay prompt-policy binding is stale")
    expected_rag_digest = rag.evidence_digest if rag is not None else None
    if overlay.rag_configuration_digest != expected_rag_digest:
        raise GovernanceError("GenAI overlay RAG binding is stale")
    if overlay.use_case_digest != use_case.evidence_digest:
        raise GovernanceError("GenAI overlay use-case binding is stale")

    if (evaluation_plan.institution_id, evaluation_plan.model_id, evaluation_plan.version_id) != expected_scope:
        raise GovernanceError("GenAI evaluation plan is outside exact dossier scope")
    if evaluation_plan.overlay_snapshot_digest != overlay.evidence_digest:
        raise GovernanceError("GenAI evaluation plan is stale for dossier overlay")
    if evaluation_assessment.plan_digest != evaluation_plan.evidence_digest:
        raise GovernanceError("GenAI evaluation assessment is bound to different plan")
    if evaluation_assessment.overlay_snapshot_digest != overlay.evidence_digest:
        raise GovernanceError("GenAI evaluation assessment is stale for dossier overlay")

    if oversight_requirement is not None:
        if oversight_requirement.use_case_digest != use_case.evidence_digest:
            raise GovernanceError("human oversight requirement is stale for dossier use case")
        if oversight_requirement.evaluation_plan_digest != evaluation_plan.evidence_digest:
            raise GovernanceError("human oversight requirement is stale for dossier evaluation plan")
    if oversight_decision is not None:
        if oversight_requirement is None:
            raise GovernanceError("human oversight decision requires oversight requirement")
        if oversight_decision.requirement_digest != oversight_requirement.evidence_digest:
            raise GovernanceError("human oversight decision is stale for requirement")
    if oversight_requirement is not None and oversight_requirement.required and oversight_decision is None:
        raise GovernanceError("required human oversight decision is missing")

    additions = [
        _entry("foundation_model_dependency", foundation.provider + ":" + foundation.provider_model_id, foundation),
        _entry("prompt_policy", prompt_policy.prompt_policy_id + ":" + prompt_policy.policy_version, prompt_policy),
        _entry("genai_use_case", use_case.use_case_id, use_case),
        _entry("genai_overlay_snapshot", overlay.version_id, overlay),
        _entry("genai_evaluation_plan", evaluation_plan.version_id, evaluation_plan),
        _entry("genai_evaluation_assessment", evaluation_assessment.version_id, evaluation_assessment),
    ]
    if rag is not None:
        additions.append(_entry("rag_configuration", rag.rag_id + ":" + rag.config_version, rag))
    if oversight_requirement is not None:
        additions.append(_entry("human_oversight_requirement", use_case.use_case_id, oversight_requirement))
    if oversight_decision is not None:
        additions.append(_entry("human_oversight_decision", use_case.use_case_id + ":" + oversight_decision.reviewer_id, oversight_decision))
    if revalidation_evidence is not None:
        if revalidation_evidence.institution_id != base_dossier.institution_id or revalidation_evidence.model_id != base_dossier.model_id:
            raise GovernanceError("GenAI revalidation evidence belongs to different dossier model")
        if revalidation_evidence.after_overlay_digest != overlay.evidence_digest:
            raise GovernanceError("GenAI revalidation evidence is stale for dossier overlay")
        additions.append(_entry("genai_revalidation_evidence", base_dossier.version_id, revalidation_evidence))

    governance_state = base_dossier.governance_state
    governance_path_complete = base_dossier.governance_path_complete
    conditions = set(base_dossier.conditions)
    gaps = set(base_dossier.gaps)

    if evaluation_assessment.state is GenAIEvaluationState.INCOMPLETE:
        governance_state = DossierGovernanceState.INCOMPLETE
        governance_path_complete = False
        gaps.add("genai_evaluation_incomplete")
    elif evaluation_assessment.state is GenAIEvaluationState.BREACHED:
        governance_state = DossierGovernanceState.REVALIDATION_REQUIRED
        governance_path_complete = False
        gaps.add("genai_evaluation_breached")
    elif evaluation_assessment.state is GenAIEvaluationState.DEGRADED:
        if governance_state is DossierGovernanceState.APPROVED:
            governance_state = DossierGovernanceState.APPROVED_WITH_CONDITIONS
        conditions.add("genai_evaluation_degraded")

    if oversight_decision is not None:
        if oversight_decision.decision is HumanOversightDecisionKind.REJECT:
            governance_state = DossierGovernanceState.REJECTED
            governance_path_complete = False
            gaps.add("human_oversight_rejected")
        elif oversight_decision.decision is HumanOversightDecisionKind.ESCALATE:
            governance_state = DossierGovernanceState.REVALIDATION_REQUIRED
            governance_path_complete = False
            gaps.add("human_oversight_escalated")

    ordered_conditions = tuple(sorted(conditions))
    ordered_gaps = tuple(sorted(gaps))
    entries = tuple(sorted((*base_dossier.entries, *additions), key=lambda item: (item.artifact_type, item.artifact_id)))
    result = GovernanceDossier(
        institution_id=base_dossier.institution_id,
        model_id=base_dossier.model_id,
        version_id=base_dossier.version_id,
        governance_state=governance_state,
        governance_path_complete=governance_path_complete,
        conditions=ordered_conditions,
        gaps=ordered_gaps,
        entries=entries,
        manifest_digest=_manifest(
            base_dossier,
            entries,
            governance_state=governance_state,
            governance_path_complete=governance_path_complete,
            conditions=ordered_conditions,
            gaps=ordered_gaps,
        ),
    )
    verify_governance_dossier(result)
    return result
