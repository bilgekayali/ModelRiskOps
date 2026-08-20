from dataclasses import replace
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from modelriskops.models import GovernanceError
from modelriskops.hardening import (
    ConfigurationChangeRegistry,
    ConfigurationChangeRequest,
    CryptoAlgorithm,
    CryptoKeyCustody,
    CryptoKeyLifecycleState,
    CryptoKeyPurpose,
    CryptoKeyStatus,
    InstitutionCryptoKeyReference,
    InstitutionCryptoKeyRegistry,
    PostgresRlsPolicy,
    TenantEnvironment,
    TenantIsolationProfile,
    TenantIsolationRegistry,
    assert_encrypted_evidence_current,
    decrypt_governance_evidence,
    encrypt_governance_evidence,
    render_postgres_rls_sql,
    sign_configuration_change,
    verify_signed_configuration_change,
)

D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class Signer:
    algorithm = CryptoAlgorithm.ED25519.value

    def __init__(self, private_key: Ed25519PrivateKey, key: InstitutionCryptoKeyReference) -> None:
        self.private_key = private_key
        self.institution_id = key.institution_id
        self.tenant_id = key.tenant_id
        self.key_id = key.key_id
        self.key_version = key.key_version

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


class Cipher:
    algorithm = CryptoAlgorithm.AES_256_GCM.value

    def __init__(self, key_bytes: bytes, key: InstitutionCryptoKeyReference) -> None:
        self.aes = AESGCM(key_bytes)
        self.institution_id = key.institution_id
        self.tenant_id = key.tenant_id
        self.key_id = key.key_id
        self.key_version = key.key_version

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self.aes.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self.aes.decrypt(nonce, ciphertext, aad)


class Fixture:
    def __init__(self) -> None:
        self.isolation = TenantIsolationRegistry()
        self.policy = PostgresRlsPolicy(
            institution_id="bank-demo", policy_id="governance-evidence", policy_version=1,
            table_name="governance_evidence", policy_name="tenant_guard",
            institution_column="institution_id", tenant_column="tenant_id",
            institution_setting="modelriskops.institution_id", tenant_setting="modelriskops.tenant_id",
            force_row_level_security=True, registered_at=100,
        )
        self.isolation.register_policy(self.policy)
        self.profile = TenantIsolationProfile(
            institution_id="bank-demo", tenant_id="tenant-a", profile_version=1,
            environment=TenantEnvironment.PRODUCTION, database_role="tenant_a_runtime",
            namespace_digest=D1, rls_policy_digests=(self.policy.evidence_digest,), registered_at=110,
        )
        self.isolation.register_profile(self.profile)

        self.keys = InstitutionCryptoKeyRegistry()
        self.signing_private = Ed25519PrivateKey.generate()
        pub = self.signing_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.signing_key = InstitutionCryptoKeyReference(
            institution_id="bank-demo", tenant_id="tenant-a", purpose=CryptoKeyPurpose.CONFIG_SIGNING,
            key_version=1, key_id="kms-signing-v1", custody=CryptoKeyCustody.KMS,
            algorithm=CryptoAlgorithm.ED25519, public_key_base64url=b64url(pub),
            not_before=100, not_after=1000, registered_at=100,
        )
        self.encryption_key = InstitutionCryptoKeyReference(
            institution_id="bank-demo", tenant_id="tenant-a", purpose=CryptoKeyPurpose.EVIDENCE_ENCRYPTION,
            key_version=1, key_id="hsm-evidence-v1", custody=CryptoKeyCustody.HSM,
            algorithm=CryptoAlgorithm.AES_256_GCM, public_key_base64url=None,
            not_before=100, not_after=1000, registered_at=100,
        )
        self.keys.register(self.signing_key)
        self.keys.register(self.encryption_key)
        self.signer = Signer(self.signing_private, self.signing_key)
        self.cipher = Cipher(bytes(range(32)), self.encryption_key)


def request(sequence: int, previous: str | None, proposed: str, at: int) -> ConfigurationChangeRequest:
    return ConfigurationChangeRequest(
        change_id=f"chg-{sequence}", institution_id="bank-demo", tenant_id="tenant-a", sequence=sequence,
        object_type="tenant-isolation-profile", object_id="tenant-a", previous_configuration_digest=previous,
        proposed_configuration_digest=proposed, change_reason_digest=D3,
        requested_by_human_id="security-admin", requested_at=at, effective_at=at,
    )


def test_rls_renderer_is_tenant_and_institution_scoped_and_forced() -> None:
    fx = Fixture()
    ddl = render_postgres_rls_sql(fx.policy)
    assert "ENABLE ROW LEVEL SECURITY" in ddl
    assert "FORCE ROW LEVEL SECURITY" in ddl
    assert "modelriskops.institution_id" in ddl and "modelriskops.tenant_id" in ddl


def test_isolation_profile_uses_current_rls_and_drift_invalidates_currentness() -> None:
    fx = Fixture()
    fx.isolation.assert_profile_current(fx.profile)
    policy_v2 = replace(fx.policy, policy_version=2, policy_name="tenant_guard_v2", registered_at=200)
    fx.isolation.register_policy(policy_v2)
    with pytest.raises(GovernanceError, match="RLS policy is stale"):
        fx.isolation.assert_profile_current(fx.profile)
    assert fx.isolation.register_profile(fx.profile) == fx.profile.evidence_digest
    with pytest.raises(GovernanceError, match="RLS policy is stale"):
        fx.isolation.register_profile(replace(fx.profile, profile_version=2, registered_at=210))


def test_symmetric_key_material_cannot_be_embedded() -> None:
    with pytest.raises(GovernanceError, match="must not be embedded"):
        InstitutionCryptoKeyReference(
            institution_id="bank-demo", tenant_id="tenant-a", purpose=CryptoKeyPurpose.EVIDENCE_ENCRYPTION,
            key_version=1, key_id="bad", custody=CryptoKeyCustody.KMS, algorithm=CryptoAlgorithm.AES_256_GCM,
            public_key_base64url="abcd", not_before=1, not_after=10, registered_at=1,
        )


def test_key_rotation_never_rolls_back_to_older_version() -> None:
    fx = Fixture()
    private2 = Ed25519PrivateKey.generate()
    pub2 = private2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key2 = replace(
        fx.signing_key, key_version=2, key_id="kms-signing-v2", public_key_base64url=b64url(pub2),
        registered_at=200, not_before=200,
    )
    fx.keys.register(key2)
    assert fx.keys.current_key("bank-demo", "tenant-a", CryptoKeyPurpose.CONFIG_SIGNING, now=210) == key2
    fx.keys.transition(CryptoKeyLifecycleState(
        institution_id="bank-demo", tenant_id="tenant-a", purpose=CryptoKeyPurpose.CONFIG_SIGNING,
        key_reference_digest=key2.evidence_digest, state_version=2,
        status=CryptoKeyStatus.RETIRED, effective_at=220,
    ))
    with pytest.raises(GovernanceError, match="no active tenant crypto key"):
        fx.keys.current_key("bank-demo", "tenant-a", CryptoKeyPurpose.CONFIG_SIGNING, now=230)
    with pytest.raises(GovernanceError):
        fx.keys.assert_new_operation_allowed(fx.signing_key, artifact_time=230, now=230)


def test_signed_configuration_chain_is_exact_and_tenant_bound() -> None:
    fx = Fixture()
    registry = ConfigurationChangeRegistry()
    req1 = request(1, None, D2, 120)
    signed1 = sign_configuration_change(
        req1, previous_change_digest=None, key_reference=fx.signing_key,
        key_registry=fx.keys, signer=fx.signer, signed_at=120, now=120,
    )
    assert verify_signed_configuration_change(signed1, key_registry=fx.keys, now=120) == req1
    registry.append(signed1, key_registry=fx.keys, now=120)

    req2 = request(2, D2, D4, 130)
    signed2 = sign_configuration_change(
        req2, previous_change_digest=signed1.evidence_digest, key_reference=fx.signing_key,
        key_registry=fx.keys, signer=fx.signer, signed_at=130, now=130,
    )
    registry.append(signed2, key_registry=fx.keys, now=130)
    assert len(registry.history("bank-demo", "tenant-a")) == 2

    req3 = request(3, D4, D5, 140)
    wrong_chain = sign_configuration_change(
        req3, previous_change_digest=D1, key_reference=fx.signing_key,
        key_registry=fx.keys, signer=fx.signer, signed_at=140, now=140,
    )
    with pytest.raises(GovernanceError, match="exact tenant change chain"):
        registry.append(wrong_chain, key_registry=fx.keys, now=140)


def test_future_effective_configuration_does_not_become_current_early() -> None:
    fx = Fixture()
    req = replace(request(1, None, D2, 120), effective_at=150)
    signed = sign_configuration_change(
        req, previous_change_digest=None, key_reference=fx.signing_key,
        key_registry=fx.keys, signer=fx.signer, signed_at=120, now=120,
    )
    with pytest.raises(GovernanceError, match="before effective_at"):
        ConfigurationChangeRegistry().append(signed, key_registry=fx.keys, now=140)


def test_encrypted_evidence_binds_tenant_profile_key_and_subject() -> None:
    fx = Fixture()
    plaintext = b"governance evidence payload"
    envelope = encrypt_governance_evidence(
        plaintext, envelope_id="env-1", institution_id="bank-demo", tenant_id="tenant-a",
        subject_artifact_digest=D2, isolation_profile=fx.profile, isolation_registry=fx.isolation,
        key_reference=fx.encryption_key, key_registry=fx.keys, encryptor=fx.cipher,
        encrypted_at=140, now=140,
    )
    assert decrypt_governance_evidence(
        envelope, isolation_registry=fx.isolation, key_registry=fx.keys, decryptor=fx.cipher, now=140
    ) == plaintext
    with pytest.raises(GovernanceError):
        decrypt_governance_evidence(
            replace(envelope, subject_artifact_digest=D3),
            isolation_registry=fx.isolation, key_registry=fx.keys, decryptor=fx.cipher, now=140,
        )


def test_isolation_drift_preserves_history_but_fails_current_eligibility() -> None:
    fx = Fixture()
    envelope = encrypt_governance_evidence(
        b"payload", envelope_id="env-2", institution_id="bank-demo", tenant_id="tenant-a",
        subject_artifact_digest=D2, isolation_profile=fx.profile, isolation_registry=fx.isolation,
        key_reference=fx.encryption_key, key_registry=fx.keys, encryptor=fx.cipher,
        encrypted_at=140, now=140,
    )
    profile_v2 = replace(fx.profile, profile_version=2, namespace_digest=D4, registered_at=200)
    fx.isolation.register_profile(profile_v2)
    assert decrypt_governance_evidence(
        envelope, isolation_registry=fx.isolation, key_registry=fx.keys, decryptor=fx.cipher, now=210
    ) == b"payload"
    with pytest.raises(GovernanceError, match="stale"):
        assert_encrypted_evidence_current(envelope, isolation_registry=fx.isolation, key_registry=fx.keys, now=210)
    with pytest.raises(GovernanceError, match="stale"):
        encrypt_governance_evidence(
            b"new", envelope_id="env-3", institution_id="bank-demo", tenant_id="tenant-a",
            subject_artifact_digest=D2, isolation_profile=fx.profile, isolation_registry=fx.isolation,
            key_reference=fx.encryption_key, key_registry=fx.keys, encryptor=fx.cipher,
            encrypted_at=210, now=210,
        )
