from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskDecision, RiskPolicyProfile
from .validation import ValidationConclusion, ValidationPlan, ValidationResolution


class ApprovalDecision(str, Enum):
    APPROVE = "approve"
    APPROVE_WITH_CONDITIONS = "approve_with_conditions"
    REJECT = "reject"


class ApprovalState(str, Enum):
    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


class RevalidationTrigger(str, Enum):
    MODEL_RECORD = "model_record"
    ARTIFACT = "artifact"
    CODE = "code"
    DATA = "data"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    BUSINESS_USE = "business_use"
    DEPLOYMENT_CONTEXT = "deployment_context"
    POLICY_PROFILE = "policy_profile"
    MONITORING_DETERIORATION = "monitoring_deterioration"
    CONTROL_DETERIORATION = "control_deterioration"


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    risk_decision_digest: str
    validation_plan_digest: str
    validation_resolution_digest: str
    required_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            if not getattr(self, name).strip():
                raise GovernanceError(f"{name} must be non-empty")
        for name in (
            "model_version_digest",
            "risk_decision_digest",
            "validation_plan_digest",
            "validation_resolution_digest",
        ):
            _require_digest(name, getattr(self, name))
        if not self.required_roles or any(not role.strip() for role in self.required_roles):
            raise GovernanceError("approval requirement must define non-empty required_roles")
        if len(self.required_roles) != len(set(self.required_roles)):
            raise GovernanceError("required_roles must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ApprovalVote:
    requirement_digest: str
    approver_id: str
    approver_role: str
    decision: ApprovalDecision
    conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_digest("requirement_digest", self.requirement_digest)
        if not self.approver_id.strip() or not self.approver_role.strip():
            raise GovernanceError("approver identity and role must be non-empty")
        cleaned = tuple(item.strip() for item in self.conditions)
        if any(not item for item in cleaned) or len(cleaned) != len(set(cleaned)):
            raise GovernanceError("approval conditions must be non-empty and unique")
        object.__setattr__(self, "conditions", cleaned)
        if self.decision is ApprovalDecision.APPROVE_WITH_CONDITIONS and not cleaned:
            raise GovernanceError("conditional approval requires conditions")
        if self.decision is ApprovalDecision.APPROVE and cleaned:
            raise GovernanceError("unconditional approval cannot carry conditions")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    requirement_digest: str
    state: ApprovalState
    vote_digests: tuple[str, ...]
    missing_roles: tuple[str, ...]
    conditions: tuple[str, ...]

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ExceptionArtifact:
    exception_id: str
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    risk_decision_digest: str
    waived_requirement_ids: tuple[str, ...]
    owner_id: str
    rationale: str
    compensating_controls: tuple[str, ...]
    issued_at: int
    expires_at: int
    one_time: bool

    def __post_init__(self) -> None:
        for name in ("exception_id", "institution_id", "model_id", "version_id", "owner_id", "rationale"):
            if not str(getattr(self, name)).strip():
                raise GovernanceError(f"{name} must be non-empty")
        _require_digest("model_version_digest", self.model_version_digest)
        _require_digest("risk_decision_digest", self.risk_decision_digest)
        if self.issued_at < 0 or self.expires_at <= self.issued_at:
            raise GovernanceError("exception expiry must be after issuance")
        _require_unique_text("waived_requirement_ids", self.waived_requirement_ids)
        _require_unique_text("compensating_controls", self.compensating_controls)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RevalidationRequirement:
    institution_id: str
    model_id: str
    before_state_digest: str
    after_state_digest: str
    triggers: tuple[RevalidationTrigger, ...]
    rationale: str

    def __post_init__(self) -> None:
        if not self.institution_id.strip() or not self.model_id.strip() or not self.rationale.strip():
            raise GovernanceError("revalidation identity and rationale must be non-empty")
        _require_digest("before_state_digest", self.before_state_digest)
        _require_digest("after_state_digest", self.after_state_digest)
        if self.before_state_digest == self.after_state_digest:
            raise GovernanceError("revalidation requires a changed governance state")
        if not self.triggers or len(self.triggers) != len(set(self.triggers)):
            raise GovernanceError("revalidation triggers must be non-empty and unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _require_digest(name: str, value: str) -> None:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")


def _require_unique_text(name: str, values: Iterable[str]) -> tuple[str, ...]:
    cleaned = tuple(item.strip() for item in values)
    if not cleaned or any(not item for item in cleaned) or len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must contain unique non-empty values")
    return cleaned


def derive_approval_requirement(
    record: ModelRecord,
    version: ModelVersion,
    risk: RiskDecision,
    plan: ValidationPlan,
    resolution: ValidationResolution,
) -> ApprovalRequirement:
    _assert_validation_chain_current(record, version, risk, plan, resolution)
    if resolution.conclusion in {ValidationConclusion.FAIL, ValidationConclusion.INCOMPLETE}:
        raise GovernanceError("terminal or incomplete validation is not approval-eligible")

    required_roles = tuple(
        role
        for role in ("senior_risk_approval", "executive_risk_acceptance")
        if role in risk.requirements
    )
    if not required_roles:
        required_roles = ("model_risk_approver",)

    return ApprovalRequirement(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        model_version_digest=version.evidence_digest,
        risk_decision_digest=risk.evidence_digest,
        validation_plan_digest=plan.evidence_digest,
        validation_resolution_digest=resolution.evidence_digest,
        required_roles=required_roles,
    )


def create_approval_vote(
    record: ModelRecord,
    requirement: ApprovalRequirement,
    *,
    approver_id: str,
    approver_role: str,
    decision: ApprovalDecision,
    conditions: Iterable[str] = (),
) -> ApprovalVote:
    if requirement.institution_id != record.institution_id or requirement.model_id != record.model_id:
        raise GovernanceError("approval requirement does not belong to model record")
    if approver_id == record.owner_id:
        raise GovernanceError("model owner cannot approve their own model")
    if approver_role not in requirement.required_roles:
        raise GovernanceError("approver role does not satisfy this requirement")
    return ApprovalVote(
        requirement_digest=requirement.evidence_digest,
        approver_id=approver_id,
        approver_role=approver_role,
        decision=decision,
        conditions=tuple(conditions),
    )


def resolve_approval(
    requirement: ApprovalRequirement,
    votes: Iterable[ApprovalVote],
) -> ApprovalResolution:
    ordered = tuple(sorted(votes, key=lambda item: (item.approver_role, item.approver_id)))
    if any(vote.requirement_digest != requirement.evidence_digest for vote in ordered):
        raise GovernanceError("approval vote is bound to a different requirement")
    roles = [vote.approver_role for vote in ordered]
    if len(roles) != len(set(roles)):
        raise GovernanceError("approval package must contain at most one vote per required role")
    approvers = [vote.approver_id for vote in ordered]
    if len(approvers) != len(set(approvers)):
        raise GovernanceError("distinct required roles must be approved by distinct people")
    if any(role not in requirement.required_roles for role in roles):
        raise GovernanceError("approval package contains an unauthorized role")

    vote_digests = tuple(vote.evidence_digest for vote in ordered)
    if any(vote.decision is ApprovalDecision.REJECT for vote in ordered):
        return ApprovalResolution(
            requirement_digest=requirement.evidence_digest,
            state=ApprovalState.REJECTED,
            vote_digests=vote_digests,
            missing_roles=(),
            conditions=(),
        )

    missing = tuple(role for role in requirement.required_roles if role not in set(roles))
    if missing:
        return ApprovalResolution(
            requirement_digest=requirement.evidence_digest,
            state=ApprovalState.INCOMPLETE,
            vote_digests=vote_digests,
            missing_roles=missing,
            conditions=(),
        )

    conditions = tuple(
        sorted({condition for vote in ordered for condition in vote.conditions})
    )
    state = (
        ApprovalState.APPROVED_WITH_CONDITIONS
        if conditions
        else ApprovalState.APPROVED
    )
    return ApprovalResolution(
        requirement_digest=requirement.evidence_digest,
        state=state,
        vote_digests=vote_digests,
        missing_roles=(),
        conditions=conditions,
    )


_NON_EXCEPTIONABLE = frozenset({"accountable_owner", "current_inventory", "independent_validation"})


def create_exception(
    version: ModelVersion,
    risk: RiskDecision,
    *,
    exception_id: str,
    waived_requirement_ids: Iterable[str],
    owner_id: str,
    rationale: str,
    compensating_controls: Iterable[str],
    issued_at: int,
    expires_at: int,
    one_time: bool = False,
) -> ExceptionArtifact:
    waived = tuple(sorted(set(waived_requirement_ids)))
    if not waived or any(item not in risk.requirements for item in waived):
        raise GovernanceError("exception scope must be a non-empty subset of current risk requirements")
    forbidden = _NON_EXCEPTIONABLE.intersection(waived)
    if forbidden:
        raise GovernanceError("exception cannot waive non-exceptionable governance requirements")
    if risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    return ExceptionArtifact(
        exception_id=exception_id,
        institution_id=risk.institution_id,
        model_id=risk.model_id,
        version_id=version.version_id,
        model_version_digest=version.evidence_digest,
        risk_decision_digest=risk.evidence_digest,
        waived_requirement_ids=waived,
        owner_id=owner_id,
        rationale=rationale,
        compensating_controls=tuple(compensating_controls),
        issued_at=issued_at,
        expires_at=expires_at,
        one_time=one_time,
    )


def assert_exception_valid(
    exception: ExceptionArtifact,
    version: ModelVersion,
    risk: RiskDecision,
    requirement_id: str,
    *,
    at_time: int,
    consumed: bool = False,
) -> None:
    if exception.model_version_digest != version.evidence_digest:
        raise GovernanceError("exception is stale for model version")
    if exception.risk_decision_digest != risk.evidence_digest:
        raise GovernanceError("exception is stale for risk decision")
    if requirement_id not in exception.waived_requirement_ids:
        raise GovernanceError("requirement is outside exception scope")
    if at_time < exception.issued_at or at_time >= exception.expires_at:
        raise GovernanceError("exception is not currently valid")
    if exception.one_time and consumed:
        raise GovernanceError("one-time exception has already been consumed")


def assert_approval_requirement_current(
    requirement: ApprovalRequirement,
    record: ModelRecord,
    version: ModelVersion,
    risk: RiskDecision,
    plan: ValidationPlan,
    resolution: ValidationResolution,
) -> None:
    _assert_validation_chain_current(record, version, risk, plan, resolution)
    expected = derive_approval_requirement(record, version, risk, plan, resolution)
    if expected.evidence_digest != requirement.evidence_digest:
        raise GovernanceError("approval requirement is stale for current governance state")


def derive_revalidation_requirement(
    before_record: ModelRecord,
    after_record: ModelRecord,
    before_version: ModelVersion,
    after_version: ModelVersion,
    before_policy: RiskPolicyProfile,
    after_policy: RiskPolicyProfile,
    *,
    operational_triggers: Iterable[RevalidationTrigger] = (),
) -> RevalidationRequirement | None:
    if before_record.institution_id != after_record.institution_id or before_record.model_id != after_record.model_id:
        raise GovernanceError("revalidation comparison must remain within one model identity")
    if before_version.institution_id != after_version.institution_id or before_version.model_id != after_version.model_id:
        raise GovernanceError("revalidation versions must belong to the same model identity")

    triggers: set[RevalidationTrigger] = set(operational_triggers)
    if before_record.evidence_digest != after_record.evidence_digest:
        triggers.add(RevalidationTrigger.MODEL_RECORD)
    if before_record.business_use != after_record.business_use:
        triggers.add(RevalidationTrigger.BUSINESS_USE)
    if before_record.deployment_context != after_record.deployment_context:
        triggers.add(RevalidationTrigger.DEPLOYMENT_CONTEXT)
    if before_version.artifact_digest != after_version.artifact_digest:
        triggers.add(RevalidationTrigger.ARTIFACT)
    if before_version.code_digest != after_version.code_digest:
        triggers.add(RevalidationTrigger.CODE)
    if before_version.data_digest != after_version.data_digest:
        triggers.add(RevalidationTrigger.DATA)
    if before_version.config_digest != after_version.config_digest:
        triggers.add(RevalidationTrigger.CONFIG)
    if sha256_digest(before_version.dependencies) != sha256_digest(after_version.dependencies):
        triggers.add(RevalidationTrigger.DEPENDENCY)
    if before_policy.evidence_digest != after_policy.evidence_digest:
        triggers.add(RevalidationTrigger.POLICY_PROFILE)

    before_state = sha256_digest(
        {
            "record": before_record.evidence_digest,
            "version": before_version.evidence_digest,
            "policy": before_policy.evidence_digest,
        }
    )
    after_state = sha256_digest(
        {
            "record": after_record.evidence_digest,
            "version": after_version.evidence_digest,
            "policy": after_policy.evidence_digest,
            "operational_triggers": sorted(item.value for item in triggers if item in {
                RevalidationTrigger.MONITORING_DETERIORATION,
                RevalidationTrigger.CONTROL_DETERIORATION,
            }),
        }
    )
    if not triggers:
        return None
    if before_state == after_state:
        after_state = sha256_digest({"state": after_state, "triggers": sorted(item.value for item in triggers)})

    ordered = tuple(sorted(triggers, key=lambda item: item.value))
    return RevalidationRequirement(
        institution_id=after_record.institution_id,
        model_id=after_record.model_id,
        before_state_digest=before_state,
        after_state_digest=after_state,
        triggers=ordered,
        rationale="Material governance state change requires revalidation: " + ", ".join(item.value for item in ordered),
    )


def _assert_validation_chain_current(
    record: ModelRecord,
    version: ModelVersion,
    risk: RiskDecision,
    plan: ValidationPlan,
    resolution: ValidationResolution,
) -> None:
    if risk.institution_id != record.institution_id or risk.model_id != record.model_id:
        raise GovernanceError("risk decision does not belong to model record")
    if risk.version_id != version.version_id or risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    if plan.institution_id != record.institution_id or plan.model_id != record.model_id:
        raise GovernanceError("validation plan does not belong to model record")
    if plan.version_id != version.version_id or plan.model_version_digest != version.evidence_digest:
        raise GovernanceError("validation plan is stale for model version")
    if plan.risk_decision_digest != risk.evidence_digest:
        raise GovernanceError("validation plan is stale for risk decision")
    if resolution.plan_digest != plan.evidence_digest:
        raise GovernanceError("validation resolution is stale for validation plan")
