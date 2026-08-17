from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

from .canonical import canonical_json, sha256_digest
from .governance import (
    ApprovalRequirement,
    ApprovalResolution,
    ApprovalState,
    ApprovalVote,
    ExceptionArtifact,
    RevalidationRequirement,
    assert_approval_requirement_current,
    resolve_approval,
)
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskDecision, RiskPolicyProfile
from .validation import (
    ValidationFinding,
    ValidationPlan,
    ValidationResolution,
    resolve_validation,
)


class DossierGovernanceState(str, Enum):
    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"
    REVALIDATION_REQUIRED = "revalidation_required"


@dataclass(frozen=True, slots=True)
class DossierEntry:
    artifact_type: str
    artifact_id: str
    digest: str
    canonical_payload: str

    def __post_init__(self) -> None:
        if not self.artifact_type.strip() or not self.artifact_id.strip():
            raise GovernanceError("dossier artifact type and id must be non-empty")
        _require_digest("dossier entry digest", self.digest)
        try:
            payload = json.loads(self.canonical_payload)
        except json.JSONDecodeError as exc:
            raise GovernanceError("dossier entry payload must be valid JSON") from exc
        if canonical_json(payload) != self.canonical_payload:
            raise GovernanceError("dossier entry payload must use canonical JSON")
        if sha256_digest(payload) != self.digest:
            raise GovernanceError("dossier entry digest does not match payload")


@dataclass(frozen=True, slots=True)
class GovernanceDossier:
    institution_id: str
    model_id: str
    version_id: str
    governance_state: DossierGovernanceState
    governance_path_complete: bool
    conditions: tuple[str, ...]
    gaps: tuple[str, ...]
    entries: tuple[DossierEntry, ...]
    manifest_digest: str

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            if not getattr(self, name).strip():
                raise GovernanceError(f"{name} must be non-empty")
        _require_digest("manifest_digest", self.manifest_digest)
        keys = [(entry.artifact_type, entry.artifact_id) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise GovernanceError("dossier entries must have unique type/id identities")
        if tuple(sorted(self.conditions)) != self.conditions or len(self.conditions) != len(set(self.conditions)):
            raise GovernanceError("dossier conditions must be sorted and unique")
        if tuple(sorted(self.gaps)) != self.gaps or len(self.gaps) != len(set(self.gaps)):
            raise GovernanceError("dossier gaps must be sorted and unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _require_digest(name: str, value: str) -> None:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")


def _entry(artifact_type: str, artifact_id: str, artifact: Any) -> DossierEntry:
    payload = canonical_json(artifact)
    return DossierEntry(
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        digest=sha256_digest(json.loads(payload)),
        canonical_payload=payload,
    )


def _manifest_payload(
    *,
    institution_id: str,
    model_id: str,
    version_id: str,
    governance_state: DossierGovernanceState,
    governance_path_complete: bool,
    conditions: tuple[str, ...],
    gaps: tuple[str, ...],
    entries: tuple[DossierEntry, ...],
) -> dict[str, Any]:
    return {
        "institution_id": institution_id,
        "model_id": model_id,
        "version_id": version_id,
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


def build_governance_dossier(
    record: ModelRecord,
    version: ModelVersion,
    policy: RiskPolicyProfile,
    risk: RiskDecision,
    plan: ValidationPlan,
    findings: Iterable[ValidationFinding],
    validation_resolution: ValidationResolution,
    approval_requirement: ApprovalRequirement,
    votes: Iterable[ApprovalVote],
    approval_resolution: ApprovalResolution,
    *,
    exceptions: Iterable[ExceptionArtifact] = (),
    revalidation_requirement: RevalidationRequirement | None = None,
) -> GovernanceDossier:
    finding_list = tuple(sorted(findings, key=lambda item: item.finding_id))
    vote_list = tuple(sorted(votes, key=lambda item: (item.approver_role, item.approver_id)))
    exception_list = tuple(sorted(exceptions, key=lambda item: item.exception_id))

    if risk.policy_digest != policy.evidence_digest:
        raise GovernanceError("risk decision is stale for policy profile")
    if risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    recomputed_validation = resolve_validation(plan, finding_list)
    if recomputed_validation != validation_resolution:
        raise GovernanceError("validation resolution does not reproduce from supplied findings")
    assert_approval_requirement_current(
        approval_requirement,
        record,
        version,
        risk,
        plan,
        validation_resolution,
    )
    recomputed_approval = resolve_approval(approval_requirement, vote_list)
    if recomputed_approval != approval_resolution:
        raise GovernanceError("approval resolution does not reproduce from supplied votes")

    for exception in exception_list:
        if exception.institution_id != record.institution_id or exception.model_id != record.model_id:
            raise GovernanceError("exception does not belong to dossier model")
        if exception.model_version_digest != version.evidence_digest:
            raise GovernanceError("exception is stale for dossier model version")
        if exception.risk_decision_digest != risk.evidence_digest:
            raise GovernanceError("exception is stale for dossier risk decision")

    gaps: set[str] = set()
    conditions: set[str] = set(approval_resolution.conditions)
    if approval_resolution.state is ApprovalState.REJECTED:
        governance_state = DossierGovernanceState.REJECTED
        gaps.add("approval_rejected")
    elif approval_resolution.state is ApprovalState.INCOMPLETE:
        governance_state = DossierGovernanceState.INCOMPLETE
        gaps.update(f"missing_approval_role:{role}" for role in approval_resolution.missing_roles)
    elif approval_resolution.state is ApprovalState.APPROVED_WITH_CONDITIONS:
        governance_state = DossierGovernanceState.APPROVED_WITH_CONDITIONS
    else:
        governance_state = DossierGovernanceState.APPROVED

    if revalidation_requirement is not None:
        if revalidation_requirement.institution_id != record.institution_id or revalidation_requirement.model_id != record.model_id:
            raise GovernanceError("revalidation requirement does not belong to dossier model")
        governance_state = DossierGovernanceState.REVALIDATION_REQUIRED
        gaps.add("revalidation_required")

    governance_path_complete = governance_state in {
        DossierGovernanceState.APPROVED,
        DossierGovernanceState.APPROVED_WITH_CONDITIONS,
    }

    entries: list[DossierEntry] = [
        _entry("model_record", record.model_id, record),
        _entry("model_version", version.version_id, version),
        _entry("risk_policy", policy.policy_id + ":" + policy.version, policy),
        _entry("risk_decision", version.version_id, risk),
        _entry("validation_plan", plan.validator_id, plan),
    ]
    entries.extend(
        _entry("validation_finding", finding.finding_id, finding)
        for finding in finding_list
    )
    entries.extend(
        [
            _entry("validation_resolution", version.version_id, validation_resolution),
            _entry("approval_requirement", version.version_id, approval_requirement),
        ]
    )
    entries.extend(
        _entry("approval_vote", vote.approver_role + ":" + vote.approver_id, vote)
        for vote in vote_list
    )
    entries.append(_entry("approval_resolution", version.version_id, approval_resolution))
    entries.extend(
        _entry("exception", exception.exception_id, exception)
        for exception in exception_list
    )
    if revalidation_requirement is not None:
        entries.append(
            _entry("revalidation_requirement", version.version_id, revalidation_requirement)
        )

    ordered_entries = tuple(sorted(entries, key=lambda item: (item.artifact_type, item.artifact_id)))
    ordered_conditions = tuple(sorted(conditions))
    ordered_gaps = tuple(sorted(gaps))
    manifest = _manifest_payload(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        governance_state=governance_state,
        governance_path_complete=governance_path_complete,
        conditions=ordered_conditions,
        gaps=ordered_gaps,
        entries=ordered_entries,
    )
    return GovernanceDossier(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        governance_state=governance_state,
        governance_path_complete=governance_path_complete,
        conditions=ordered_conditions,
        gaps=ordered_gaps,
        entries=ordered_entries,
        manifest_digest=sha256_digest(manifest),
    )


def verify_governance_dossier(dossier: GovernanceDossier) -> None:
    for entry in dossier.entries:
        try:
            payload = json.loads(entry.canonical_payload)
        except json.JSONDecodeError as exc:
            raise GovernanceError("dossier contains invalid artifact JSON") from exc
        if canonical_json(payload) != entry.canonical_payload:
            raise GovernanceError("dossier artifact payload is not canonical")
        if sha256_digest(payload) != entry.digest:
            raise GovernanceError("dossier artifact digest verification failed")

    expected_manifest = sha256_digest(
        _manifest_payload(
            institution_id=dossier.institution_id,
            model_id=dossier.model_id,
            version_id=dossier.version_id,
            governance_state=dossier.governance_state,
            governance_path_complete=dossier.governance_path_complete,
            conditions=dossier.conditions,
            gaps=dossier.gaps,
            entries=dossier.entries,
        )
    )
    if expected_manifest != dossier.manifest_digest:
        raise GovernanceError("dossier manifest digest verification failed")


def dossier_from_dict(payload: dict[str, Any]) -> GovernanceDossier:
    expected_keys = {
        "institution_id",
        "model_id",
        "version_id",
        "governance_state",
        "governance_path_complete",
        "conditions",
        "gaps",
        "entries",
        "manifest_digest",
    }
    if set(payload) != expected_keys:
        raise GovernanceError("dossier document contains missing or unknown fields")
    try:
        entries = tuple(
            DossierEntry(
                artifact_type=item["artifact_type"],
                artifact_id=item["artifact_id"],
                digest=item["digest"],
                canonical_payload=item["canonical_payload"],
            )
            for item in payload["entries"]
        )
        dossier = GovernanceDossier(
            institution_id=payload["institution_id"],
            model_id=payload["model_id"],
            version_id=payload["version_id"],
            governance_state=DossierGovernanceState(payload["governance_state"]),
            governance_path_complete=payload["governance_path_complete"],
            conditions=tuple(payload["conditions"]),
            gaps=tuple(payload["gaps"]),
            entries=entries,
            manifest_digest=payload["manifest_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GovernanceError("dossier document has invalid structure") from exc
    verify_governance_dossier(dossier)
    return dossier
