from __future__ import annotations

from typing import Iterable

from .dossier import GovernanceDossier
from .genai import (
    FoundationModelDependency,
    GenAIEvaluationAssessment,
    GenAIEvaluationObservation,
    GenAIEvaluationPlan,
    GenAIOverlaySnapshot,
    GenAIRevalidationEvidence,
    GenAIUseCaseProfile,
    HumanOversightDecision,
    HumanOversightRequirement,
    PromptPolicyArtifact,
    RAGConfiguration,
    assess_genai_evaluation as _assess_genai_evaluation,
)
from .genai_dossier import build_genai_governance_dossier as _build_genai_governance_dossier
from .models import GovernanceError


def assess_genai_evaluation(
    plan: GenAIEvaluationPlan,
    overlay: GenAIOverlaySnapshot,
    observations: Iterable[GenAIEvaluationObservation],
    *,
    evaluated_at: int,
) -> GenAIEvaluationAssessment:
    observation_list = tuple(observations)
    if evaluated_at < plan.planned_at:
        raise GovernanceError("GenAI evaluation cannot predate evaluation plan")
    if any(observation.observed_at < plan.planned_at for observation in observation_list):
        raise GovernanceError("GenAI observation cannot predate evaluation plan")
    return _assess_genai_evaluation(
        plan,
        overlay,
        observation_list,
        evaluated_at=evaluated_at,
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
    version_entries = [
        entry
        for entry in base_dossier.entries
        if entry.artifact_type == "model_version" and entry.artifact_id == base_dossier.version_id
    ]
    if len(version_entries) != 1:
        raise GovernanceError("base dossier must contain exactly one exact model_version entry")
    if version_entries[0].digest != evaluation_plan.model_version_digest:
        raise GovernanceError("GenAI evaluation plan is stale for base dossier model version")
    return _build_genai_governance_dossier(
        base_dossier,
        foundation,
        prompt_policy,
        use_case,
        overlay,
        evaluation_plan,
        evaluation_assessment,
        rag=rag,
        oversight_requirement=oversight_requirement,
        oversight_decision=oversight_decision,
        revalidation_evidence=revalidation_evidence,
    )
