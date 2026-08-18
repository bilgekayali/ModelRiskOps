from __future__ import annotations

import json
from typing import Iterable, Mapping

from .canonical import canonical_json, sha256_digest
from .change_control import (
    ChangeAuthorizationRequirement,
    ChangeAuthorizationResolution,
    ChangeAuthorizationState,
    ChangeAuthorizationVote,
    ChangeImplementationEvidence,
    ModelChangeProposal,
)
from .dossier import DossierEntry, GovernanceDossier, verify_governance_dossier
from .models import GovernanceError
from .signing import SignedGovernanceEnvelope, SigningKeyRegistry, verify_signed_envelope


def _entry(artifact_type: str, artifact_id: str, artifact) -> DossierEntry:
    payload = canonical_json(artifact)
    return DossierEntry(
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        digest=sha256_digest(json.loads(payload)),
        canonical_payload=payload,
    )


def _manifest(dossier: GovernanceDossier, entries: tuple[DossierEntry, ...]) -> str:
    return sha256_digest(
        {
            "institution_id": dossier.institution_id,
            "model_id": dossier.model_id,
            "version_id": dossier.version_id,
            "governance_state": dossier.governance_state.value,
            "governance_path_complete": dossier.governance_path_complete,
            "conditions": list(dossier.conditions),
            "gaps": list(dossier.gaps),
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


def build_signed_change_dossier(
    base_dossier: GovernanceDossier,
    proposal: ModelChangeProposal,
    requirement: ChangeAuthorizationRequirement,
    votes: Iterable[ChangeAuthorizationVote],
    signatures_by_vote_digest: Mapping[str, SignedGovernanceEnvelope],
    authorization: ChangeAuthorizationResolution,
    signing_registry: SigningKeyRegistry,
    *,
    implementation: ChangeImplementationEvidence | None = None,
) -> GovernanceDossier:
    """Append already-governed signed change evidence to an exact governance dossier.

    This helper re-verifies signature integrity and artifact bindings. It does not
    replace `resolve_change_authorization`, infer materiality, or authorize deployment.
    """
    verify_governance_dossier(base_dossier)
    if base_dossier.institution_id != proposal.institution_id or base_dossier.model_id != proposal.model_id:
        raise GovernanceError("change proposal does not belong to base governance dossier model")
    if base_dossier.version_id != proposal.after_version_id:
        raise GovernanceError("base governance dossier is not for the proposed after version")
    if requirement.proposal_digest != proposal.evidence_digest:
        raise GovernanceError("change authorization requirement is bound to different proposal")
    if authorization.requirement_digest != requirement.evidence_digest:
        raise GovernanceError("change authorization resolution is bound to different requirement")
    if authorization.proposal_digest != proposal.evidence_digest:
        raise GovernanceError("change authorization resolution is bound to different proposal")

    ordered_votes = tuple(sorted(votes, key=lambda item: (item.approver_role, item.approver_id)))
    expected_vote_digests = tuple(vote.evidence_digest for vote in ordered_votes)
    if expected_vote_digests != authorization.vote_digests:
        raise GovernanceError("change authorization vote set does not match resolution evidence")

    signature_entries: list[DossierEntry] = []
    expected_signature_digests: list[str] = []
    for vote in ordered_votes:
        envelope = signatures_by_vote_digest.get(vote.evidence_digest)
        if envelope is None:
            raise GovernanceError("signed change dossier requires one signature per authorization vote")
        verify_signed_envelope(
            vote,
            envelope,
            signing_registry,
            institution_id=proposal.institution_id,
            model_id=proposal.model_id,
            version_id=proposal.after_version_id,
            artifact_type="model_change_authorization_vote",
            signing_purpose="authorize_model_change",
            at_time=authorization.resolved_at,
        )
        expected_signature_digests.append(envelope.evidence_digest)
        signature_entries.append(
            _entry("signed_change_authorization_vote", vote.approver_role + ":" + vote.approver_id, envelope)
        )
    if tuple(expected_signature_digests) != authorization.signature_digests:
        raise GovernanceError("change authorization signature set does not match resolution evidence")

    if authorization.state is not ChangeAuthorizationState.AUTHORIZED and implementation is not None:
        raise GovernanceError("implementation evidence cannot be packaged for non-authorized change")
    if implementation is not None:
        if implementation.proposal_digest != proposal.evidence_digest:
            raise GovernanceError("implementation evidence is bound to different proposal")
        if implementation.authorization_resolution_digest != authorization.evidence_digest:
            raise GovernanceError("implementation evidence is bound to different authorization resolution")
        if implementation.authorized_after_state_digest != proposal.after_state_digest:
            raise GovernanceError("implementation evidence is bound to different authorized after state")

    additions: list[DossierEntry] = [
        _entry("model_change_proposal", proposal.change_id, proposal),
        _entry("change_authorization_requirement", proposal.change_id, requirement),
    ]
    additions.extend(
        _entry("change_authorization_vote", vote.approver_role + ":" + vote.approver_id, vote)
        for vote in ordered_votes
    )
    additions.extend(signature_entries)
    additions.append(_entry("change_authorization_resolution", proposal.change_id, authorization))
    if implementation is not None:
        additions.append(_entry("change_implementation", proposal.change_id, implementation))

    entries = tuple(sorted((*base_dossier.entries, *additions), key=lambda item: (item.artifact_type, item.artifact_id)))
    result = GovernanceDossier(
        institution_id=base_dossier.institution_id,
        model_id=base_dossier.model_id,
        version_id=base_dossier.version_id,
        governance_state=base_dossier.governance_state,
        governance_path_complete=base_dossier.governance_path_complete,
        conditions=base_dossier.conditions,
        gaps=base_dossier.gaps,
        entries=entries,
        manifest_digest=_manifest(base_dossier, entries),
    )
    verify_governance_dossier(result)
    return result
