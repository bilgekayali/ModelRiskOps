import json
from pathlib import Path

import jsonschema

from modelriskops import canonical_json
from modelriskops.portfolio import default_portfolio_risk_policy
from tests.test_portfolio import PortfolioFixture, permissive_policy


ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def test_real_v05_provider_dependency_and_exit_artifacts_match_strict_schemas() -> None:
    fx = PortfolioFixture()
    jsonschema.validate(payload(fx.provider), schema("third-party-provider-profile.schema.json"))
    jsonschema.validate(payload(fx.dep_a), schema("third-party-model-dependency.schema.json"))
    jsonschema.validate(payload(fx.dep_b), schema("third-party-model-dependency.schema.json"))
    jsonschema.validate(payload(fx.exit_a), schema("third-party-exit-plan.schema.json"))
    jsonschema.validate(payload(fx.exit_b), schema("third-party-exit-plan.schema.json"))


def test_real_v05_portfolio_policy_snapshot_assessment_and_package_match_schemas() -> None:
    fx = PortfolioFixture()
    policy = permissive_policy()
    assessment = fx.registry.assess_portfolio(fx.snapshot, policy, assessed_at=160)
    package = fx.registry.build_evidence_package(fx.snapshot, policy, assessment, generated_at=170)
    jsonschema.validate(payload(policy), schema("portfolio-risk-policy.schema.json"))
    jsonschema.validate(payload(default_portfolio_risk_policy("bank-demo")), schema("portfolio-risk-policy.schema.json"))
    jsonschema.validate(payload(fx.snapshot), schema("portfolio-snapshot.schema.json"))
    jsonschema.validate(payload(assessment), schema("portfolio-assessment.schema.json"))
    jsonschema.validate(payload(package), schema("portfolio-evidence-package.schema.json"))


def test_v05_schemas_reject_unknown_fields_and_pin_closed_enums() -> None:
    dependency = schema("third-party-model-dependency.schema.json")
    assert dependency["additionalProperties"] is False
    assert dependency["properties"]["materiality"]["enum"] == ["non_material", "material", "critical"]
    assert dependency["properties"]["substitutability"]["enum"] == ["high", "moderate", "low", "none"]
    assert dependency["properties"]["data_access_level"]["enum"] == ["none", "non_sensitive", "personal", "sensitive"]

    policy = schema("portfolio-risk-policy.schema.json")
    assert policy["properties"]["require_exit_plan_for_material"]["const"] is True
    assert policy["properties"]["require_tested_exit_for_critical"]["const"] is True
    assert policy["properties"]["degrade_low_substitutability"]["const"] is True

    assessment = schema("portfolio-assessment.schema.json")
    assert assessment["properties"]["state"]["enum"] == ["healthy", "degraded", "breached", "incomplete"]
