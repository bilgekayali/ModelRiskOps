import json
from pathlib import Path

import jsonschema

import modelriskops
import modelriskops.api as stable_api
from modelriskops.cli import STABLE_CLI_COMMANDS, contract_snapshot
from modelriskops.stability import REQUIRED_SECURITY_REVIEW_ITEMS, REQUIRED_V1_NON_CLAIMS

ROOT = Path(__file__).resolve().parents[1]


def test_v1_package_and_public_api_baseline_are_exact() -> None:
    baseline = json.loads((ROOT / "compatibility/v1-public-api.json").read_text(encoding="utf-8"))
    assert modelriskops.__version__ == "1.0.0"
    assert baseline["release_version"] == "1.0.0"
    assert list(stable_api.__all__) == baseline["python_api_symbols"]
    assert list(STABLE_CLI_COMMANDS) == baseline["cli_commands"]


def test_contract_snapshot_is_deterministic_and_non_executing() -> None:
    first = contract_snapshot()
    second = contract_snapshot()
    assert first == second
    assert first["release_version"] == "1.0.0"
    assert first["compatibility_series"] == "v1"
    assert first["python_api_symbols"] == list(stable_api.__all__)
    assert first["cli_commands"] == list(STABLE_CLI_COMMANDS)
    assert first["execution_performed"] is False


def test_v1_schema_file_set_is_exact_and_all_schemas_remain_valid() -> None:
    baseline = json.loads((ROOT / "compatibility/v1-schema-baseline.json").read_text(encoding="utf-8"))
    current = sorted(path.name for path in (ROOT / "schemas").glob("*.schema.json"))
    assert current == baseline["schema_files"]
    for filename in current:
        payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        jsonschema.Draft202012Validator.check_schema(payload)

    for filename in (
        "stable-compatibility-policy.schema.json",
        "public-surface-manifest.schema.json",
        "supported-upgrade-path.schema.json",
        "independent-security-review-checklist.schema.json",
        "responsibility-scope.schema.json",
        "stable-release-baseline.schema.json",
    ):
        payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert payload["additionalProperties"] is False


def test_v1_review_and_nonclaim_sets_are_canonical() -> None:
    assert len(REQUIRED_SECURITY_REVIEW_ITEMS) == 12
    assert tuple(sorted(REQUIRED_SECURITY_REVIEW_ITEMS)) == REQUIRED_SECURITY_REVIEW_ITEMS
    assert len(REQUIRED_V1_NON_CLAIMS) == 9
    assert tuple(sorted(REQUIRED_V1_NON_CLAIMS)) == REQUIRED_V1_NON_CLAIMS


def test_v1_machine_contract_constants_are_fail_closed() -> None:
    compatibility = json.loads((ROOT / "schemas/stable-compatibility-policy.schema.json").read_text())
    assert compatibility["properties"]["stable_since_version"]["const"] == "1.0.0"
    assert compatibility["properties"]["breaking_change_requires_major"]["const"] is True
    assert compatibility["properties"]["unknown_json_fields_rejected"]["const"] is True

    upgrade = json.loads((ROOT / "schemas/supported-upgrade-path.schema.json").read_text())
    assert upgrade["properties"]["source_series"]["const"] == "0.8.x"
    assert upgrade["properties"]["target_version"]["const"] == "1.0.0"
    assert upgrade["properties"]["backup_required"]["const"] is True
    assert upgrade["properties"]["breaking_changes_declared"]["const"] is False

    review = json.loads((ROOT / "schemas/independent-security-review-checklist.schema.json").read_text())
    assert review["properties"]["reviewed_repository_digest"]["pattern"] == "^[0-9a-f]{64}$"
    assert review["properties"]["reviewer_independence_confirmed"]["const"] is True
    assert review["properties"]["items"]["minItems"] == 12
    assert review["properties"]["items"]["maxItems"] == 12

    scope = json.loads((ROOT / "schemas/responsibility-scope.schema.json").read_text())
    for field in (
        "legal_advice_provided",
        "regulatory_compliance_determined",
        "certification_claimed",
        "supervisory_acceptance_claimed",
        "production_fitness_claimed",
    ):
        assert scope["properties"][field]["const"] is False
