import json
from pathlib import Path

import jsonschema

from modelriskops import (
    RevalidationTrigger,
    canonical_json,
    derive_revalidation_requirement,
)
from tests.test_dossier import approved_chain, build_approved_dossier


ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def test_real_approval_artifacts_match_strict_schema() -> None:
    (
        _,
        _,
        _,
        _,
        _,
        _,
        requirement,
        votes,
        approval_resolution,
        _,
    ) = approved_chain()
    approval_schema = schema("approval.schema.json")
    jsonschema.validate(payload(requirement), approval_schema)
    for vote in votes:
        jsonschema.validate(payload(vote), approval_schema)
    jsonschema.validate(payload(approval_resolution), approval_schema)


def test_real_exception_matches_strict_schema() -> None:
    exception = approved_chain()[-1]
    jsonschema.validate(payload(exception), schema("exception.schema.json"))


def test_real_revalidation_requirement_matches_strict_schema() -> None:
    record, version, policy, *_ = approved_chain()
    revalidation = derive_revalidation_requirement(
        record,
        record,
        version,
        version,
        policy,
        policy,
        operational_triggers=(RevalidationTrigger.CONTROL_DETERIORATION,),
    )
    assert revalidation is not None
    jsonschema.validate(
        payload(revalidation),
        schema("revalidation-requirement.schema.json"),
    )


def test_real_governance_dossier_matches_strict_schema() -> None:
    dossier = build_approved_dossier()
    jsonschema.validate(payload(dossier), schema("governance-dossier.schema.json"))
