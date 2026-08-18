from dataclasses import replace

import pytest

from modelriskops import (
    GovernanceError,
    KeyRevocation,
    SigningKeyRegistry,
    VerificationKeyRecord,
    create_signed_envelope,
    public_key_base64_from_private_seed,
    verify_signed_envelope,
)


SEED_A = b"a" * 32
SEED_B = b"b" * 32


def key_record(*, seed: bytes = SEED_A, key_id: str = "key-1", roles=("model_risk_approver",)):
    return VerificationKeyRecord(
        institution_id="bank-a",
        key_id=key_id,
        owner_id="approver-1",
        public_key_base64=public_key_base64_from_private_seed(seed),
        permitted_roles=tuple(roles),
        valid_from=100,
        valid_until=1000,
        registered_at=90,
    )


def test_signed_governance_envelope_round_trip_and_tamper_detection() -> None:
    registry = SigningKeyRegistry()
    key = key_record()
    registry.register_key(key)
    artifact = {"decision": "approve", "evidence": "x" * 64}

    envelope = create_signed_envelope(
        artifact,
        registry,
        key,
        private_key_seed=SEED_A,
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="v2",
        artifact_type="approval_vote",
        signer_id="approver-1",
        signer_role="model_risk_approver",
        signing_purpose="approve_model",
        signed_at=150,
    )
    assert verify_signed_envelope(
        artifact,
        envelope,
        registry,
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="v2",
        artifact_type="approval_vote",
        signing_purpose="approve_model",
        at_time=160,
    ) == envelope.evidence_digest

    with pytest.raises(GovernanceError, match="evaluation time cannot precede"):
        verify_signed_envelope(
            artifact,
            envelope,
            registry,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signing_purpose="approve_model",
            at_time=149,
        )

    with pytest.raises(GovernanceError, match="artifact digest"):
        verify_signed_envelope(
            {"decision": "reject", "evidence": "x" * 64},
            envelope,
            registry,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signing_purpose="approve_model",
        )

    bad_signature = replace(envelope, signature_base64="A" * 86 + "==")
    with pytest.raises(GovernanceError, match="invalid Ed25519"):
        verify_signed_envelope(
            artifact,
            bad_signature,
            registry,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signing_purpose="approve_model",
        )


def test_wrong_private_key_role_and_scope_fail_closed() -> None:
    registry = SigningKeyRegistry()
    key = key_record()
    registry.register_key(key)
    artifact = {"a": 1}

    with pytest.raises(GovernanceError, match="private key"):
        create_signed_envelope(
            artifact,
            registry,
            key,
            private_key_seed=SEED_B,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signer_id="approver-1",
            signer_role="model_risk_approver",
            signing_purpose="approve_model",
            signed_at=150,
        )

    with pytest.raises(GovernanceError, match="permitted roles"):
        create_signed_envelope(
            artifact,
            registry,
            key,
            private_key_seed=SEED_A,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signer_id="approver-1",
            signer_role="executive_risk_acceptance",
            signing_purpose="approve_model",
            signed_at=150,
        )

    with pytest.raises(GovernanceError, match="institution"):
        create_signed_envelope(
            artifact,
            registry,
            key,
            private_key_seed=SEED_A,
            institution_id="bank-b",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="approval_vote",
            signer_id="approver-1",
            signer_role="model_risk_approver",
            signing_purpose="approve_model",
            signed_at=150,
        )


def test_revocation_preserves_historical_verification_but_blocks_current_use() -> None:
    registry = SigningKeyRegistry()
    key = key_record()
    registry.register_key(key)
    artifact = {"decision": "authorize"}
    envelope = create_signed_envelope(
        artifact,
        registry,
        key,
        private_key_seed=SEED_A,
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="v2",
        artifact_type="change_vote",
        signer_id="approver-1",
        signer_role="model_risk_approver",
        signing_purpose="authorize_change",
        signed_at=150,
    )
    registry.revoke_key(
        KeyRevocation(
            institution_id="bank-a",
            key_id=key.key_id,
            key_digest=key.evidence_digest,
            revoked_by_id="security-admin",
            reason="key rotation",
            revoked_at=200,
        )
    )

    verify_signed_envelope(
        artifact,
        envelope,
        registry,
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="v2",
        artifact_type="change_vote",
        signing_purpose="authorize_change",
    )
    with pytest.raises(GovernanceError, match="revoked"):
        verify_signed_envelope(
            artifact,
            envelope,
            registry,
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="v2",
            artifact_type="change_vote",
            signing_purpose="authorize_change",
            at_time=250,
        )


def test_key_identity_is_immutable_and_snapshot_is_deterministic() -> None:
    registry = SigningKeyRegistry()
    key = key_record()
    first = registry.register_key(key)
    second = registry.register_key(key)
    assert first == second
    snapshot = registry.snapshot_digest()
    assert snapshot == registry.snapshot_digest()

    conflicting = replace(key, permitted_roles=("change_control_approver",))
    with pytest.raises(GovernanceError, match="different key content"):
        registry.register_key(conflicting)
