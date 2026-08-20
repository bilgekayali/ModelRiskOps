import json
from pathlib import Path

import jsonschema

from modelriskops.canonical import canonical_json
from modelriskops.hardening import (
    ConfigurationChangeRequest,
    CryptoKeyLifecycleState,
    CryptoKeyPurpose,
    CryptoKeyStatus,
    sign_configuration_change,
    encrypt_governance_evidence,
)
from tests.test_hardening import Fixture

ROOT = Path(__file__).resolve().parents[1]


def payload(value):
    return json.loads(canonical_json(value))


def schema(name: str) -> dict:
    result = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(result)
    assert result["additionalProperties"] is False
    return result


def test_v07_runtime_artifacts_match_strict_schemas() -> None:
    fx = Fixture()
    lifecycle = CryptoKeyLifecycleState(
        institution_id="bank-demo", tenant_id="tenant-a", purpose=CryptoKeyPurpose.CONFIG_SIGNING,
        key_reference_digest=fx.signing_key.evidence_digest, state_version=2,
        status=CryptoKeyStatus.RETIRED, effective_at=300,
    )
    request = ConfigurationChangeRequest(
        change_id="schema-change", institution_id="bank-demo", tenant_id="tenant-a", sequence=1,
        object_type="tenant-isolation-profile", object_id="tenant-a", previous_configuration_digest=None,
        proposed_configuration_digest="2" * 64, change_reason_digest="3" * 64,
        requested_by_human_id="security-admin", requested_at=120, effective_at=120,
    )
    signed = sign_configuration_change(
        request, previous_change_digest=None, key_reference=fx.signing_key, key_registry=fx.keys,
        signer=fx.signer, signed_at=120, now=120,
    )
    encrypted = encrypt_governance_evidence(
        b"payload", envelope_id="schema-envelope", institution_id="bank-demo", tenant_id="tenant-a",
        subject_artifact_digest="4" * 64, isolation_profile=fx.profile, isolation_registry=fx.isolation,
        key_reference=fx.encryption_key, key_registry=fx.keys, encryptor=fx.cipher, encrypted_at=140, now=140,
    )
    fixtures = {
        "postgres-rls-policy.schema.json": fx.policy,
        "tenant-isolation-profile.schema.json": fx.profile,
        "institution-crypto-key-reference.schema.json": fx.signing_key,
        "crypto-key-lifecycle-state.schema.json": lifecycle,
        "configuration-change-request.schema.json": request,
        "signed-configuration-change.schema.json": signed,
        "encrypted-governance-evidence.schema.json": encrypted,
    }
    for name, artifact in fixtures.items():
        jsonschema.Draft202012Validator(schema(name)).validate(payload(artifact))


def test_encryption_key_schema_forbids_embedded_key_material() -> None:
    fx = Fixture()
    contract = schema("institution-crypto-key-reference.schema.json")
    bad = payload(fx.encryption_key)
    bad["public_key_base64url"] = "abcd"
    errors = list(jsonschema.Draft202012Validator(contract).iter_errors(bad))
    assert errors


def test_signed_change_schema_locks_algorithm() -> None:
    contract = schema("signed-configuration-change.schema.json")
    assert contract["properties"]["algorithm"]["const"] == "Ed25519"


def test_encrypted_evidence_schema_locks_algorithm() -> None:
    contract = schema("encrypted-governance-evidence.schema.json")
    assert contract["properties"]["algorithm"]["const"] == "AES-256-GCM"
