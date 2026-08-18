from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from .canonical import sha256_digest
from .governance import (
    ApprovalRequirement,
    ApprovalResolution,
    ApprovalState,
    RevalidationRequirement,
    RevalidationTrigger,
    assert_approval_requirement_current,
    derive_revalidation_requirement,
)
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskDecision, RiskPolicyProfile
from .signing import SignedGovernanceEnvelope, SigningKeyRegistry, verify_signed_envelope
from .validation import ValidationPlan, ValidationResolution


class ChangeMateriality(str, Enum):
    NON_MATERIAL = "non_material"
    MATERIAL = "material"


class ChangeAuthorizationDecision(str, Enum):
    AUTHORIZE = "authorize"
    REJECT = "reject"


class ChangeAuthorizationState(str, Enum):
    AUTHORIZED = "authorized"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _roles(values: Iterable[str]) -> tuple[str, ...]:
    roles = tuple(_text("required_roles", item) for item in values)
    if not roles or len(roles) != len(set(roles)):
        raise GovernanceError("required_roles must contain unique non-empty roles")
    return roles


def _state_digest(record: ModelRecord, version: ModelVersion, policy: RiskPolicyProfile) -> str:
    return sha256_digest(
        {
            "model_record_digest": record.evidence_digest,
            "model_version_digest": version.evidence_digest,
            "risk_policy_digest": policy.evidence_digest,
        }
    )


@dataclass(frozen=True, slots=True)
class ModelChangeProposal:
    change_id: str
    institution_id: str
    model_id: str
    before_version_id: str
    after_version_id: str
    before_record_digest: str
    after_record_digest: str
    before_version_digest: str
    after_version_digest: str
    before_policy_digest: str
    after_policy_digest: str
    before_state_digest: str
    after_state_digest: str
    materiality: ChangeMateriality
    materiality_owner_id: str
    materiality_rationale: str
    revalidation_requirement_digest: str | None
    proposed_at: int

    def __post_init__(self) -> None:
        for name in (
            "change_id",
            "institution_id",
            "model_id",
            "before_version_id",
            "after_version_id",
            "materiality_owner_id",
            "materiality_rationale",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "before_record_digest",
            "after_record_digest",
            "before_version_digest",
            "after_version_digest",
            "before_policy_digest",
            "after_policy_digest",
            "before_state_digest",
            "after_state_digest",
        ):
            _digest(name, getattr(self, name))
        if self.before_state_digest == self.after_state_digest:
            raise GovernanceError("model change proposal requires a changed governance state")
        if not isinstance(self.materiality, ChangeMateriality):
            raise GovernanceError("materiality must be a ChangeMateriality")
        if self.revalidation_requirement_digest is not None:
            _digest("revalidation_requirement_digest", self.revalidation_requirement_digest)
        if self.materiality is ChangeMateriality.MATERIAL and self.revalidation_requirement_digest is None:
            raise GovernanceError("material change requires revalidation requirement evidence")
        _timestamp("proposed_at", self.proposed_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ChangeAuthorizationRequirement:
    proposal_digest: str
    institution_id: str
    model_id: str
    after_version_id: str
    materiality: ChangeMateriality
    required_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest("proposal_digest", self.proposal_digest)
        for name in ("institution_id", "model_id", "after_version_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.materiality, ChangeMateriality):
            raise GovernanceError("materiality must be a ChangeMateriality")
        object.__setattr__(self, "required_roles", _roles(self.required_roles))
        if self.materiality is ChangeMateriality.MATERIAL and len(self.required_roles) < 2:
            raise GovernanceError("material change requires at least two independent authorization roles")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ChangeAuthorizationVote:
    requirement_digest: str
    proposal_digest: str
    approver_id: str
    approver_role: str
    decision: ChangeAuthorizationDecision
    rationale: str
    decided_at: int

    def __post_init__(self) -> None:
        _digest("requirement_digest", self.requirement_digest)
        _digest("proposal_digest", self.proposal_digest)
        for name in ("approver_id", "approver_role", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.decision, ChangeAuthorizationDecision):
            raise GovernanceError("decision must be a ChangeAuthorizationDecision")
        _timestamp("decided_at", self.decided_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ChangeAuthorizationResolution:
    requirement_digest: str
    proposal_digest: str
    state: ChangeAuthorizationState
    vote_digests: tuple[str, ...]
    signature_digests: tuple[str, ...]
    missing_roles: tuple[str, ...]
    revalidation_requirement_digest: str | None
    approval_requirement_digest: str | None
    approval_resolution_digest: str | None
    resolved_at: int
    automated_deployment_authorized: bool = False
    regulatory_approval_determined: bool = False

    def __post_init__(self) -> None:
        _digest("requirement_digest", self.requirement_digest)
        _digest("proposal_digest", self.proposal_digest)
        if not isinstance(self.state, ChangeAuthorizationState):
            raise GovernanceError("state must be a ChangeAuthorizationState")
        for name in ("vote_digests", "signature_digests"):
            values = getattr(self, name)
            if len(values) != len(set(values)):
                raise GovernanceError(f"{name} must be unique")
            for item in values:
                _digest(name, item)
        if len(self.missing_roles) != len(set(self.missing_roles)) or any(not item.strip() for item in self.missing_roles):
            raise GovernanceError("missing_roles must be unique non-empty roles")
        for name in (
            "revalidation_requirement_digest",
            "approval_requirement_digest",
            "approval_resolution_digest",
        ):
            value = getattr(self, name)
            if value is not None:
                _digest(name, value)
        _timestamp("resolved_at", self.resolved_at)
        if self.automated_deployment_authorized:
            raise GovernanceError("change authorization does not authorize automated deployment")
        if self.regulatory_approval_determined:
            raise GovernanceError("change authorization does not determine regulatory approval")
        if self.state is ChangeAuthorizationState.AUTHORIZED and self.missing_roles:
            raise GovernanceError("authorized change cannot have missing authorization roles")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ChangeImplementationEvidence:
    change_id: str
    institution_id: str
    model_id: str
    after_version_id: str
    proposal_digest: str
    authorization_resolution_digest: str
    authorized_after_state_digest: str
    implemented_by_id: str
    implementation_evidence_digest: str
    implemented_at: int
    deployment_executed_by_modelriskops: bool = False

    def __post_init__(self) -> None:
        for name in ("change_id", "institution_id", "model_id", "after_version_id", "implemented_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "proposal_digest",
            "authorization_resolution_digest",
            "authorized_after_state_digest",
            "implementation_evidence_digest",
        ):
            _digest(name, getattr(self, name))
        _timestamp("implemented_at", self.implemented_at)
        if self.deployment_executed_by_modelriskops:
            raise GovernanceError("ModelRiskOps change evidence does not execute deployment")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def create_model_change_proposal(
    before_record: ModelRecord,
    after_record: ModelRecord,
    before_version: ModelVersion,
    after_version: ModelVersion,
    before_policy: RiskPolicyProfile,
    after_policy: RiskPolicyProfile,
    *,
    change_id: str,
    materiality: ChangeMateriality,
    materiality_owner_id: str,
    materiality_rationale: str,
    proposed_at: int,
    operational_triggers: Iterable[RevalidationTrigger] = (),
) -> ModelChangeProposal:
    if not isinstance(materiality, ChangeMateriality):
        raise GovernanceError("materiality must be an explicit ChangeMateriality")
    if before_record.institution_id != after_record.institution_id or before_record.model_id != after_record.model_id:
        raise GovernanceError("model change must remain within one institution/model identity")
    if before_version.institution_id != before_record.institution_id or after_version.institution_id != after_record.institution_id:
        raise GovernanceError("model versions must match model-record institution")
    if before_version.model_id != before_record.model_id or after_version.model_id != after_record.model_id:
        raise GovernanceError("model versions must match model-record identity")

    revalidation = derive_revalidation_requirement(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
        operational_triggers=operational_triggers,
    )
    before_state = _state_digest(before_record, before_version, before_policy)
    after_state = _state_digest(after_record, after_version, after_policy)
    if before_state == after_state and revalidation is None:
        raise GovernanceError("change proposal requires changed model/version/policy state or operational trigger")
    if before_state == after_state:
        after_state = sha256_digest(
            {
                "state": after_state,
                "operational_triggers": sorted(item.value for item in operational_triggers),
            }
        )

    return ModelChangeProposal(
        change_id=change_id,
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
        materiality_owner_id=materiality_owner_id,
        materiality_rationale=materiality_rationale,
        revalidation_requirement_digest=(revalidation.evidence_digest if revalidation is not None else None),
        proposed_at=proposed_at,
    )


def assert_change_proposal_current(
    proposal: ModelChangeProposal,
    before_record: ModelRecord,
    after_record: ModelRecord,
    before_version: ModelVersion,
    after_version: ModelVersion,
    before_policy: RiskPolicyProfile,
    after_policy: RiskPolicyProfile,
    *,
    operational_triggers: Iterable[RevalidationTrigger] = (),
) -> RevalidationRequirement | None:
    expected = create_model_change_proposal(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
        change_id=proposal.change_id,
        materiality=proposal.materiality,
        materiality_owner_id=proposal.materiality_owner_id,
        materiality_rationale=proposal.materiality_rationale,
        proposed_at=proposal.proposed_at,
        operational_triggers=operational_triggers,
    )
    if expected.evidence_digest != proposal.evidence_digest:
        raise GovernanceError("model change proposal is stale for current before/after governance state")
    return derive_revalidation_requirement(
        before_record,
        after_record,
        before_version,
        after_version,
        before_policy,
        after_policy,
        operational_triggers=operational_triggers,
    )


def derive_change_authorization_requirement(
    proposal: ModelChangeProposal,
    *,
    required_roles: Iterable[str] | None = None,
) -> ChangeAuthorizationRequirement:
    if required_roles is None:
        roles = (
            ("model_risk_approver", "change_control_approver")
            if proposal.materiality is ChangeMateriality.MATERIAL
            else ("change_control_approver",)
        )
    else:
        roles = tuple(required_roles)
    return ChangeAuthorizationRequirement(
        proposal_digest=proposal.evidence_digest,
        institution_id=proposal.institution_id,
        model_id=proposal.model_id,
        after_version_id=proposal.after_version_id,
        materiality=proposal.materiality,
        required_roles=roles,
    )


def create_change_authorization_vote(
    proposal: ModelChangeProposal,
    requirement: ChangeAuthorizationRequirement,
    *,
    approver_id: str,
    approver_role: str,
    decision: ChangeAuthorizationDecision,
    rationale: str,
    decided_at: int,
) -> ChangeAuthorizationVote:
    if requirement.proposal_digest != proposal.evidence_digest:
        raise GovernanceError("change authorization requirement is bound to different proposal")
    if approver_role not in requirement.required_roles:
        raise GovernanceError("approver role does not satisfy change authorization requirement")
    if approver_id == proposal.materiality_owner_id:
        raise GovernanceError("materiality decision owner cannot authorize the same change")
    return ChangeAuthorizationVote(
        requirement_digest=requirement.evidence_digest,
        proposal_digest=proposal.evidence_digest,
        approver_id=approver_id,
        approver_role=approver_role,
        decision=decision,
        rationale=rationale,
        decided_at=decided_at,
    )


def resolve_change_authorization(
    proposal: ModelChangeProposal,
    requirement: ChangeAuthorizationRequirement,
    votes: Iterable[ChangeAuthorizationVote],
    signatures_by_vote_digest: Mapping[str, SignedGovernanceEnvelope],
    signing_registry: SigningKeyRegistry,
    *,
    resolved_at: int,
    revalidation_requirement: RevalidationRequirement | None = None,
    after_record: ModelRecord | None = None,
    after_version: ModelVersion | None = None,
    after_risk: RiskDecision | None = None,
    validation_plan: ValidationPlan | None = None,
    validation_resolution: ValidationResolution | None = None,
    approval_requirement: ApprovalRequirement | None = None,
    approval_resolution: ApprovalResolution | None = None,
) -> ChangeAuthorizationResolution:
    _timestamp("resolved_at", resolved_at)
    if requirement.proposal_digest != proposal.evidence_digest:
        raise GovernanceError("change authorization requirement is stale for proposal")

    ordered = tuple(sorted(votes, key=lambda item: (item.approver_role, item.approver_id)))
    if any(vote.requirement_digest != requirement.evidence_digest for vote in ordered):
        raise GovernanceError("change authorization vote is bound to different requirement")
    if any(vote.proposal_digest != proposal.evidence_digest for vote in ordered):
        raise GovernanceError("change authorization vote is bound to different proposal")
    roles = [vote.approver_role for vote in ordered]
    approvers = [vote.approver_id for vote in ordered]
    if len(roles) != len(set(roles)):
        raise GovernanceError("change authorization package may contain at most one vote per role")
    if len(approvers) != len(set(approvers)):
        raise GovernanceError("distinct change authorization roles require distinct people")
    if any(role not in requirement.required_roles for role in roles):
        raise GovernanceError("change authorization package contains unauthorized role")

    signature_digests: list[str] = []
    for vote in ordered:
        envelope = signatures_by_vote_digest.get(vote.evidence_digest)
        if envelope is None:
            raise GovernanceError("each change authorization vote requires signed governance evidence")
        if envelope.signer_id != vote.approver_id or envelope.signer_role != vote.approver_role:
            raise GovernanceError("change authorization signature signer does not match vote identity/role")
        if envelope.signed_at < vote.decided_at:
            raise GovernanceError("change authorization signature cannot predate vote decision")
        verify_signed_envelope(
            vote,
            envelope,
            signing_registry,
            institution_id=proposal.institution_id,
            model_id=proposal.model_id,
            version_id=proposal.after_version_id,
            artifact_type="model_change_authorization_vote",
            signing_purpose="authorize_model_change",
            at_time=resolved_at,
        )
        signature_digests.append(envelope.evidence_digest)

    vote_digests = tuple(vote.evidence_digest for vote in ordered)
    if any(vote.decision is ChangeAuthorizationDecision.REJECT for vote in ordered):
        return ChangeAuthorizationResolution(
            requirement_digest=requirement.evidence_digest,
            proposal_digest=proposal.evidence_digest,
            state=ChangeAuthorizationState.REJECTED,
            vote_digests=vote_digests,
            signature_digests=tuple(signature_digests),
            missing_roles=(),
            revalidation_requirement_digest=proposal.revalidation_requirement_digest,
            approval_requirement_digest=None,
            approval_resolution_digest=None,
            resolved_at=resolved_at,
        )

    missing = tuple(role for role in requirement.required_roles if role not in set(roles))
    if missing:
        return ChangeAuthorizationResolution(
            requirement_digest=requirement.evidence_digest,
            proposal_digest=proposal.evidence_digest,
            state=ChangeAuthorizationState.INCOMPLETE,
            vote_digests=vote_digests,
            signature_digests=tuple(signature_digests),
            missing_roles=missing,
            revalidation_requirement_digest=proposal.revalidation_requirement_digest,
            approval_requirement_digest=None,
            approval_resolution_digest=None,
            resolved_at=resolved_at,
        )

    approval_requirement_digest: str | None = None
    approval_resolution_digest: str | None = None
    if proposal.materiality is ChangeMateriality.MATERIAL:
        if revalidation_requirement is None:
            raise GovernanceError("material change authorization requires current revalidation evidence")
        if revalidation_requirement.evidence_digest != proposal.revalidation_requirement_digest:
            raise GovernanceError("material change revalidation evidence is stale for proposal")
        required_objects = (
            after_record,
            after_version,
            after_risk,
            validation_plan,
            validation_resolution,
            approval_requirement,
            approval_resolution,
        )
        if any(item is None for item in required_objects):
            raise GovernanceError("material change authorization requires complete current after-state approval evidence")
        assert after_record is not None
        assert after_version is not None
        assert after_risk is not None
        assert validation_plan is not None
        assert validation_resolution is not None
        assert approval_requirement is not None
        assert approval_resolution is not None
        if after_record.institution_id != proposal.institution_id or after_record.model_id != proposal.model_id:
            raise GovernanceError("material change after-state approval belongs to different model")
        if after_version.version_id != proposal.after_version_id or after_version.evidence_digest != proposal.after_version_digest:
            raise GovernanceError("material change approval evidence is stale for after model version")
        assert_approval_requirement_current(
            approval_requirement,
            after_record,
            after_version,
            after_risk,
            validation_plan,
            validation_resolution,
        )
        if approval_resolution.requirement_digest != approval_requirement.evidence_digest:
            raise GovernanceError("approval resolution is bound to different approval requirement")
        if approval_resolution.state not in {ApprovalState.APPROVED, ApprovalState.APPROVED_WITH_CONDITIONS}:
            raise GovernanceError("material change requires approved current after-state governance")
        approval_requirement_digest = approval_requirement.evidence_digest
        approval_resolution_digest = approval_resolution.evidence_digest

    return ChangeAuthorizationResolution(
        requirement_digest=requirement.evidence_digest,
        proposal_digest=proposal.evidence_digest,
        state=ChangeAuthorizationState.AUTHORIZED,
        vote_digests=vote_digests,
        signature_digests=tuple(signature_digests),
        missing_roles=(),
        revalidation_requirement_digest=proposal.revalidation_requirement_digest,
        approval_requirement_digest=approval_requirement_digest,
        approval_resolution_digest=approval_resolution_digest,
        resolved_at=resolved_at,
    )


def create_change_implementation_evidence(
    proposal: ModelChangeProposal,
    authorization: ChangeAuthorizationResolution,
    after_record: ModelRecord,
    after_version: ModelVersion,
    after_policy: RiskPolicyProfile,
    *,
    implemented_by_id: str,
    implementation_evidence_digest: str,
    implemented_at: int,
) -> ChangeImplementationEvidence:
    if authorization.proposal_digest != proposal.evidence_digest:
        raise GovernanceError("change authorization is bound to different proposal")
    if authorization.state is not ChangeAuthorizationState.AUTHORIZED:
        raise GovernanceError("change implementation evidence requires authorized change")
    if after_record.institution_id != proposal.institution_id or after_record.model_id != proposal.model_id:
        raise GovernanceError("implemented after state belongs to different model")
    if after_version.version_id != proposal.after_version_id:
        raise GovernanceError("implemented version does not match authorized after version")
    if after_record.evidence_digest != proposal.after_record_digest:
        raise GovernanceError("implemented model record differs from authorized after state")
    if after_version.evidence_digest != proposal.after_version_digest:
        raise GovernanceError("implemented model version differs from authorized after state")
    if after_policy.evidence_digest != proposal.after_policy_digest:
        raise GovernanceError("implemented risk policy differs from authorized after state")
    current_state = _state_digest(after_record, after_version, after_policy)
    if current_state != proposal.after_state_digest:
        raise GovernanceError("implemented governance state differs from authorized after state")
    if implemented_at < authorization.resolved_at:
        raise GovernanceError("change implementation cannot predate authorization")
    return ChangeImplementationEvidence(
        change_id=proposal.change_id,
        institution_id=proposal.institution_id,
        model_id=proposal.model_id,
        after_version_id=proposal.after_version_id,
        proposal_digest=proposal.evidence_digest,
        authorization_resolution_digest=authorization.evidence_digest,
        authorized_after_state_digest=proposal.after_state_digest,
        implemented_by_id=implemented_by_id,
        implementation_evidence_digest=implementation_evidence_digest,
        implemented_at=implemented_at,
    )


def assert_change_implementation_current(
    implementation: ChangeImplementationEvidence,
    proposal: ModelChangeProposal,
    authorization: ChangeAuthorizationResolution,
    after_record: ModelRecord,
    after_version: ModelVersion,
    after_policy: RiskPolicyProfile,
) -> None:
    expected = create_change_implementation_evidence(
        proposal,
        authorization,
        after_record,
        after_version,
        after_policy,
        implemented_by_id=implementation.implemented_by_id,
        implementation_evidence_digest=implementation.implementation_evidence_digest,
        implemented_at=implementation.implemented_at,
    )
    if expected.evidence_digest != implementation.evidence_digest:
        raise GovernanceError("change implementation evidence is stale for current authorized state")
