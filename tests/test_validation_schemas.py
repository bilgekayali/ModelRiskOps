import json
from pathlib import Path

import jsonschema

from modelriskops import (
    FactorLevel,
    FactorName,
    FindingSeverity,
    FindingStatus,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    RiskFactor,
    TestStatus,
    ValidationDomain,
    ValidationFinding,
    ValidationTest,
    assess_model_risk,
    build_validation_plan,
    canonical_json,
    default_policy,
    resolve_validation,
)


ROOT = Path(__file__).resolve().parents[1]
D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def artifacts():
    record = ModelRecord(
        institution_id="bank-a",
        model_id="credit-risk",
        name="Credit Risk Model",
        owner_id="model-owner",
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
        RiskFactor(factor=factor, level=FactorLevel.CRITICAL)
        for factor in FactorName
    )
    risk = assess_model_risk(record, version, factors, (), default_policy("bank-a"))
    tests = (
        ValidationTest(
            test_id="concept",
            domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
            mandatory=True,
            status=TestStatus.PASS,
            evidence_digest=D5,
        ),
    )
    plan = build_validation_plan(
        record,
        version,
        risk,
        validator_id="independent-validator",
        validator_role="model-validation",
        independent_from_owner=True,
        tests=tests,
    )
    finding = ValidationFinding(
        finding_id="F-001",
        test_id="concept",
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.CLOSED,
        evidence_digest=D5,
        description="Issue remediated and independently retested.",
        remediation_digest=D6,
        closed_by_validator_id="independent-validator",
    )
    resolution = resolve_validation(plan, (finding,))
    return plan, finding, resolution


def test_validation_artifacts_match_strict_schemas() -> None:
    plan, finding, resolution = artifacts()
    jsonschema.validate(
        json.loads(canonical_json(plan)),
        schema("validation-plan.schema.json"),
    )
    jsonschema.validate(
        json.loads(canonical_json(finding)),
        schema("validation-finding.schema.json"),
    )
    jsonschema.validate(
        json.loads(canonical_json(resolution)),
        schema("validation-resolution.schema.json"),
    )


def test_validation_schemas_are_valid_draft_2020_12() -> None:
    for name in (
        "validation-plan.schema.json",
        "validation-finding.schema.json",
        "validation-resolution.schema.json",
    ):
        jsonschema.Draft202012Validator.check_schema(schema(name))
