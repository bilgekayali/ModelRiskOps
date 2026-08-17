import json
from pathlib import Path

import jsonschema

from modelriskops import (
    FactorLevel,
    FactorName,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    RiskFactor,
    assess_model_risk,
    canonical_json,
    default_policy,
)


ROOT = Path(__file__).resolve().parents[1]
D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_default_policy_matches_strict_schema() -> None:
    payload = json.loads(canonical_json(default_policy("bank-a")))
    jsonschema.validate(payload, load_schema("risk-policy.schema.json"))


def test_risk_decision_matches_strict_schema() -> None:
    record = ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="risk-owner-17",
        business_use="Credit underwriting decision support",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.VALIDATION,
        deployment_context="Internal underwriting service",
    )
    version = ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="2026.08.1",
        artifact_digest=D1,
        code_digest=D2,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
    )
    factors = tuple(
        RiskFactor(factor=factor, level=FactorLevel.MODERATE)
        for factor in FactorName
    )
    decision = assess_model_risk(record, version, factors, (), default_policy("bank-a"))
    payload = json.loads(canonical_json(decision))
    jsonschema.validate(payload, load_schema("risk-decision.schema.json"))
