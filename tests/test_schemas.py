import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def test_schemas_are_valid_draft_2020_12() -> None:
    for path in SCHEMA_DIR.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_model_record_schema_rejects_unknown_fields() -> None:
    schema = load_schema("model-record.schema.json")
    payload = {
        "institution_id": "bank-a",
        "model_id": "credit-risk",
        "name": "Credit Risk Model",
        "owner_id": "risk-owner-17",
        "business_use": "Credit underwriting decision support",
        "model_type": "machine_learning",
        "lifecycle_state": "proposed",
        "deployment_context": "Internal underwriting service",
        "intended_users": ["credit-risk-team"],
        "prohibited_uses": ["fully-autonomous-decline"],
        "unexpected_security_relevant_field": True,
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)


def test_model_version_schema_accepts_exact_digest_bound_version() -> None:
    schema = load_schema("model-version.schema.json")
    payload = {
        "institution_id": "bank-a",
        "model_id": "credit-risk",
        "version_id": "2026.08.1",
        "artifact_digest": D1,
        "code_digest": D2,
        "data_digest": D3,
        "config_digest": D4,
        "provenance_source": "institution-model-registry",
        "dependencies": [
            {
                "kind": "dataset",
                "identifier": "underwriting-features",
                "version": "2026-08-01",
                "digest": D5,
            }
        ],
    }
    jsonschema.validate(payload, schema)


def test_model_version_schema_rejects_non_sha256_digest() -> None:
    schema = load_schema("model-version.schema.json")
    payload = {
        "institution_id": "bank-a",
        "model_id": "credit-risk",
        "version_id": "2026.08.1",
        "artifact_digest": "not-a-digest",
        "code_digest": D2,
        "data_digest": D3,
        "config_digest": D4,
        "provenance_source": "institution-model-registry",
        "dependencies": [],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(payload, schema)
