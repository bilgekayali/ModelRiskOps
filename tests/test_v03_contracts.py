import json
from pathlib import Path

import jsonschema
import pytest

import modelriskops
from modelriskops import (
    ChangeAuthorizationDecision,
    ChangeMateriality,
    GovernanceError,
    KeyRevocation,
    canonical_json,
    create_change_implementation_evidence,
    resolve_change_authorization,
)
from tests.test_change_control import material_change_package, signing_fixture


ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict:
    result = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(result)
    return result


def payload(value):
    return json.loads(canonical_json(value))


def test_version_is_v0_3_0() -> None:
    assert modelriskops.__version__ == "0.3.0"


def test_new_v03_schemas_are_strict_and_accept_runtime_artifacts() -> None:
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
    resolution = resolve_change_authorization(
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
        resolution,
        after_record,
        after_version,
        policy,
        implemented_by_id="release-engineer",
        implementation_evidence_digest="9" * 64,
        implemented_at=180,
    )
    _, risk_key, _ = signing_fixture()
    revocation = KeyRevocation(
        institution_id="bank-a",
        key_id=risk_key.key_id,
        key_digest=risk_key.evidence_digest,
        revoked_by_id="security-admin",
        reason="rotation",
        revoked_at=900,
    )

    fixtures = {
        "verification-key.schema.json": [risk_key],
        "key-revocation.schema.json": [revocation],
        "signed-governance-envelope.schema.json": list(signatures.values()),
        "model-change-proposal.schema.json": [proposal],
        "change-authorization.schema.json": [requirement, *votes, resolution],
        "change-implementation.schema.json": [implementation],
    }
    for name, artifacts in fixtures.items():
        contract = schema(name)
        if contract.get("type") == "object":
            assert contract["additionalProperties"] is False
        for artifact in artifacts:
            jsonschema.Draft202012Validator(contract).validate(payload(artifact))


def test_change_authorization_schema_locks_non_claim_booleans() -> None:
    contract = schema("change-authorization.schema.json")
    resolution = contract["$defs"]["resolution"]
    assert resolution["properties"]["automated_deployment_authorized"]["const"] is False
    assert resolution["properties"]["regulatory_approval_determined"]["const"] is False


def test_raw_string_enums_do_not_bypass_v03_runtime_contracts() -> None:
    package = material_change_package()
    proposal, requirement = package[:2]
    with pytest.raises(GovernanceError, match="ChangeMateriality"):
        type(proposal)(
            change_id=proposal.change_id,
            institution_id=proposal.institution_id,
            model_id=proposal.model_id,
            before_version_id=proposal.before_version_id,
            after_version_id=proposal.after_version_id,
            before_record_digest=proposal.before_record_digest,
            after_record_digest=proposal.after_record_digest,
            before_version_digest=proposal.before_version_digest,
            after_version_digest=proposal.after_version_digest,
            before_policy_digest=proposal.before_policy_digest,
            after_policy_digest=proposal.after_policy_digest,
            before_state_digest=proposal.before_state_digest,
            after_state_digest=proposal.after_state_digest,
            materiality="material",
            materiality_owner_id=proposal.materiality_owner_id,
            materiality_rationale=proposal.materiality_rationale,
            revalidation_requirement_digest=proposal.revalidation_requirement_digest,
            proposed_at=proposal.proposed_at,
        )

    vote_type = type(package[2][0])
    with pytest.raises(GovernanceError, match="ChangeAuthorizationDecision"):
        vote_type(
            requirement_digest=requirement.evidence_digest,
            proposal_digest=proposal.evidence_digest,
            approver_id="x",
            approver_role="model_risk_approver",
            decision="authorize",
            rationale="x",
            decided_at=1,
        )
