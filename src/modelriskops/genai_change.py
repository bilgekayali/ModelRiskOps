from __future__ import annotations

from typing import Iterable

from .canonical import sha256_digest
from .change_control import ChangeMateriality, ModelChangeProposal
from .genai import GenAIOverlaySnapshot, GenAIRevalidationEvidence, GenAIRevalidationTrigger
from .governance import RevalidationRequirement, RevalidationTrigger
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskPolicyProfile


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _assert_scope(record: ModelRecord, version: ModelVersion, overlay: GenAIOverlaySnapshot) -> None:
    if (record.institution_id, record.model_id) != (version.institution_id, version.model_id):
        raise GovernanceError("model record/version scope mismatch")
    if (overlay.institution_id, overlay.model_id, overlay.version_id) != (
        version.institution_id,
        version.model_id,
        version.version_id,
    ):
        raise GovernanceError("GenAI overlay is stale for exact model version")


def _state_digest(
    record: ModelRecord,
    version: ModelVersion,
    policy: RiskPolicyProfile,
    overlay: GenAIOverlaySnapshot,
) -> str:
    return sha256_digest(
        {
            "model_record_digest": record.evidence_digest,
            "model_version_digest": version.evidence_digest,
            "risk_policy_digest": policy.evidence_digest,
            "genai_overlay_digest": overlay.evidence_digest,
        }
    )


def create_genai_model_change_proposal(
    before_record: ModelRecord,
    after_record: ModelRecord,
    before_version: ModelVersion,
    after_version: ModelVersion,
    before_policy: RiskPolicyProfile,
    after_policy: RiskPolicyProfile,
    before_overlay: GenAIOverlaySnapshot,
    after_overlay: GenAIOverlaySnapshot,
    *,
    change_id: str,
    materiality: ChangeMateriality,
    materiality_owner_id: str,
    materiality_rationale: str,
    proposed_at: int,
    triggers: Iterable[GenAIRevalidationTrigger],
    revalidation_rationale: str,
) -> tuple[ModelChangeProposal, RevalidationRequirement, GenAIRevalidationEvidence]:
    """Create v0.3-compatible signed change-control evidence bound to exact GenAI overlay state.

    Materiality remains an explicit accountable input. GenAI trigger classification is
    explicit evidence and never changes materiality automatically.
    """
    if not isinstance(materiality, ChangeMateriality):
        raise GovernanceError("materiality must be an explicit ChangeMateriality")
    if (before_record.institution_id, before_record.model_id) != (after_record.institution_id, after_record.model_id):
        raise GovernanceError("GenAI change must remain within one institution/model identity")
    _assert_scope(before_record, before_version, before_overlay)
    _assert_scope(after_record, after_version, after_overlay)
    if before_policy.institution_id != before_record.institution_id or after_policy.institution_id != after_record.institution_id:
        raise GovernanceError("risk policy institution must match GenAI change model")

    ordered = tuple(sorted(tuple(triggers), key=lambda item: item.value))
    if not ordered or len(ordered) != len(set(ordered)):
        raise GovernanceError("GenAI change requires unique explicit revalidation triggers")
    if any(not isinstance(item, GenAIRevalidationTrigger) for item in ordered):
        raise GovernanceError("GenAI change triggers must use GenAIRevalidationTrigger")

    before_state = _state_digest(before_record, before_version, before_policy, before_overlay)
    after_state = sha256_digest(
        {
            "state": _state_digest(after_record, after_version, after_policy, after_overlay),
            "genai_triggers": [item.value for item in ordered],
        }
    )
    if before_state == after_state:
        raise GovernanceError("GenAI change proposal requires changed governed state")

    revalidation = RevalidationRequirement(
        institution_id=after_record.institution_id,
        model_id=after_record.model_id,
        before_state_digest=before_state,
        after_state_digest=after_state,
        triggers=(RevalidationTrigger.CONTROL_DETERIORATION,),
        rationale=_text("revalidation_rationale", revalidation_rationale),
    )
    genai_evidence = GenAIRevalidationEvidence(
        institution_id=after_record.institution_id,
        model_id=after_record.model_id,
        before_overlay_digest=before_overlay.evidence_digest,
        after_overlay_digest=after_overlay.evidence_digest,
        triggers=ordered,
        revalidation_requirement_digest=revalidation.evidence_digest,
        rationale=revalidation_rationale,
    )

    proposal = ModelChangeProposal(
        change_id=_text("change_id", change_id),
        institution_id=after_record.institution_id,
        model_id=after_record.model_id,
        before_version_id=before_version.version_id,
        after_version_id=after_version.version_id,
        before_record_digest=before_record.evidence_digest,
        after_record_digest=after_record.evidence_digest,
        before_version_digest=before_version.evidence_digest,
        after_version_digest=after_version.evidence_digest,
        before_policy_digest=before_policy.evidence_digest,
        after_policy_digest=after_policy.evidence_digest,
        before_state_digest=before_state,
        after_state_digest=after_state,
        materiality=materiality,
        materiality_owner_id=_text("materiality_owner_id", materiality_owner_id),
        materiality_rationale=_text("materiality_rationale", materiality_rationale),
        revalidation_requirement_digest=revalidation.evidence_digest,
        proposed_at=_timestamp("proposed_at", proposed_at),
    )
    return proposal, revalidation, genai_evidence


def assert_genai_change_proposal_current(
    proposal: ModelChangeProposal,
    revalidation: RevalidationRequirement,
    genai_evidence: GenAIRevalidationEvidence,
    before_record: ModelRecord,
    after_record: ModelRecord,
    before_version: ModelVersion,
    after_version: ModelVersion,
    before_policy: RiskPolicyProfile,
    after_policy: RiskPolicyProfile,
    before_overlay: GenAIOverlaySnapshot,
    after_overlay: GenAIOverlaySnapshot,
) -> None:
    expected_proposal, expected_revalidation, expected_genai = create_genai_model_change_proposal(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
        before_overlay,
        after_overlay,
        change_id=proposal.change_id,
        materiality=proposal.materiality,
        materiality_owner_id=proposal.materiality_owner_id,
        materiality_rationale=proposal.materiality_rationale,
        proposed_at=proposal.proposed_at,
        triggers=genai_evidence.triggers,
        revalidation_rationale=genai_evidence.rationale,
    )
    if expected_proposal.evidence_digest != proposal.evidence_digest:
        raise GovernanceError("GenAI change proposal is stale for current overlay/model state")
    if expected_revalidation.evidence_digest != revalidation.evidence_digest:
        raise GovernanceError("GenAI revalidation requirement is stale for current overlay/model state")
    if expected_genai.evidence_digest != genai_evidence.evidence_digest:
        raise GovernanceError("GenAI revalidation evidence is stale for current overlay state")
