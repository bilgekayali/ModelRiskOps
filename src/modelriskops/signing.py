from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import canonical_json, sha256_digest
from .models import GovernanceError


def _required_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _require_digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _roles(values: Iterable[str]) -> tuple[str, ...]:
    roles = tuple(_required_text("permitted_roles", item) for item in values)
    if not roles or len(roles) != len(set(roles)):
        raise GovernanceError("permitted_roles must contain unique non-empty roles")
    return roles


def _decode_b64(name: str, value: str, *, expected_length: int) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error and malformed input
        raise GovernanceError(f"{name} must be valid base64") from exc
    if len(decoded) != expected_length:
        raise GovernanceError(f"{name} must decode to {expected_length} bytes")
    return decoded


@dataclass(frozen=True, slots=True)
class VerificationKeyRecord:
    institution_id: str
    key_id: str
    owner_id: str
    public_key_base64: str
    permitted_roles: tuple[str, ...]
    valid_from: int
    valid_until: int | None
    registered_at: int
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        for name in ("institution_id", "key_id", "owner_id"):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        if self.algorithm != "ed25519":
            raise GovernanceError("only ed25519 verification keys are supported")
        _decode_b64("public_key_base64", self.public_key_base64, expected_length=32)
        object.__setattr__(self, "permitted_roles", _roles(self.permitted_roles))
        for name in ("valid_from", "registered_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GovernanceError(f"{name} must be a non-negative integer timestamp")
        if self.valid_until is not None:
            if isinstance(self.valid_until, bool) or not isinstance(self.valid_until, int):
                raise GovernanceError("valid_until must be an integer timestamp or null")
            if self.valid_until <= self.valid_from:
                raise GovernanceError("valid_until must be after valid_from")
        if self.registered_at > self.valid_from:
            raise GovernanceError("registered_at cannot be after valid_from")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class KeyRevocation:
    institution_id: str
    key_id: str
    key_digest: str
    revoked_by_id: str
    reason: str
    revoked_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "key_id", "revoked_by_id", "reason"):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        _require_digest("key_digest", self.key_digest)
        if isinstance(self.revoked_at, bool) or not isinstance(self.revoked_at, int) or self.revoked_at < 0:
            raise GovernanceError("revoked_at must be a non-negative integer timestamp")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class SignedGovernanceEnvelope:
    institution_id: str
    model_id: str
    version_id: str | None
    artifact_type: str
    artifact_digest: str
    signer_id: str
    signer_role: str
    key_id: str
    key_digest: str
    signing_purpose: str
    signed_at: int
    signature_base64: str
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        for name in (
            "institution_id",
            "model_id",
            "artifact_type",
            "signer_id",
            "signer_role",
            "key_id",
            "signing_purpose",
        ):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        if self.version_id is not None:
            object.__setattr__(self, "version_id", _required_text("version_id", self.version_id))
        _require_digest("artifact_digest", self.artifact_digest)
        _require_digest("key_digest", self.key_digest)
        if self.algorithm != "ed25519":
            raise GovernanceError("only ed25519 signed envelopes are supported")
        if isinstance(self.signed_at, bool) or not isinstance(self.signed_at, int) or self.signed_at < 0:
            raise GovernanceError("signed_at must be a non-negative integer timestamp")
        _decode_b64("signature_base64", self.signature_base64, expected_length=64)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class SigningKeyRegistry:
    """Institution-scoped public verification keys and immutable revocation evidence."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], VerificationKeyRecord] = {}
        self._revocations: dict[tuple[str, str], KeyRevocation] = {}

    def register_key(self, key: VerificationKeyRecord) -> str:
        identity = (key.institution_id, key.key_id)
        existing = self._keys.get(identity)
        if existing is not None and existing.evidence_digest != key.evidence_digest:
            raise GovernanceError("key_id is already registered with different key content")
        self._keys.setdefault(identity, key)
        return key.evidence_digest

    def key(self, institution_id: str, key_id: str) -> VerificationKeyRecord:
        try:
            return self._keys[(institution_id, key_id)]
        except KeyError as exc:
            raise GovernanceError("unknown verification key") from exc

    def revoke_key(self, revocation: KeyRevocation) -> str:
        key = self.key(revocation.institution_id, revocation.key_id)
        if key.evidence_digest != revocation.key_digest:
            raise GovernanceError("key revocation is bound to different key content")
        if revocation.revoked_at < key.valid_from:
            raise GovernanceError("key cannot be revoked before its validity begins")
        identity = (revocation.institution_id, revocation.key_id)
        existing = self._revocations.get(identity)
        if existing is not None and existing.evidence_digest != revocation.evidence_digest:
            raise GovernanceError("verification key already has different revocation evidence")
        self._revocations.setdefault(identity, revocation)
        return revocation.evidence_digest

    def revocation(self, institution_id: str, key_id: str) -> KeyRevocation | None:
        return self._revocations.get((institution_id, key_id))

    def assert_key_active(self, key: VerificationKeyRecord, *, at_time: int) -> None:
        if at_time < key.valid_from:
            raise GovernanceError("verification key is not yet valid")
        if key.valid_until is not None and at_time >= key.valid_until:
            raise GovernanceError("verification key is expired")
        revocation = self.revocation(key.institution_id, key.key_id)
        if revocation is not None and at_time >= revocation.revoked_at:
            raise GovernanceError("verification key is revoked")

    def snapshot_digest(self) -> str:
        return sha256_digest(
            {
                "keys": sorted(key.evidence_digest for key in self._keys.values()),
                "revocations": sorted(item.evidence_digest for item in self._revocations.values()),
            }
        )


def public_key_base64_from_private_seed(private_key_seed: bytes) -> str:
    if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
        raise GovernanceError("private_key_seed must be exactly 32 bytes")
    public_bytes = Ed25519PrivateKey.from_private_bytes(private_key_seed).public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode("ascii")


def _signature_payload(
    artifact: Any,
    *,
    institution_id: str,
    model_id: str,
    version_id: str | None,
    artifact_type: str,
    signer_id: str,
    signer_role: str,
    key_id: str,
    key_digest: str,
    signing_purpose: str,
    signed_at: int,
) -> bytes:
    return canonical_json(
        {
            "artifact": artifact,
            "artifact_digest": sha256_digest(artifact),
            "institution_id": institution_id,
            "model_id": model_id,
            "version_id": version_id,
            "artifact_type": artifact_type,
            "signer_id": signer_id,
            "signer_role": signer_role,
            "key_id": key_id,
            "key_digest": key_digest,
            "signing_purpose": signing_purpose,
            "signed_at": signed_at,
            "algorithm": "ed25519",
        }
    ).encode("utf-8")


def create_signed_envelope(
    artifact: Any,
    registry: SigningKeyRegistry,
    key: VerificationKeyRecord,
    *,
    private_key_seed: bytes,
    institution_id: str,
    model_id: str,
    version_id: str | None,
    artifact_type: str,
    signer_id: str,
    signer_role: str,
    signing_purpose: str,
    signed_at: int,
) -> SignedGovernanceEnvelope:
    registered = registry.key(key.institution_id, key.key_id)
    if registered.evidence_digest != key.evidence_digest:
        raise GovernanceError("signing key is not the registered key content")
    if institution_id != key.institution_id:
        raise GovernanceError("signed artifact institution does not match verification key")
    if signer_id != key.owner_id:
        raise GovernanceError("signer_id must match registered verification-key owner")
    if signer_role not in key.permitted_roles:
        raise GovernanceError("signer_role is outside verification-key permitted roles")
    registry.assert_key_active(key, at_time=signed_at)
    if public_key_base64_from_private_seed(private_key_seed) != key.public_key_base64:
        raise GovernanceError("private key does not match registered public verification key")

    payload = _signature_payload(
        artifact,
        institution_id=institution_id,
        model_id=model_id,
        version_id=version_id,
        artifact_type=artifact_type,
        signer_id=signer_id,
        signer_role=signer_role,
        key_id=key.key_id,
        key_digest=key.evidence_digest,
        signing_purpose=signing_purpose,
        signed_at=signed_at,
    )
    signature = Ed25519PrivateKey.from_private_bytes(private_key_seed).sign(payload)
    return SignedGovernanceEnvelope(
        institution_id=institution_id,
        model_id=model_id,
        version_id=version_id,
        artifact_type=artifact_type,
        artifact_digest=sha256_digest(artifact),
        signer_id=signer_id,
        signer_role=signer_role,
        key_id=key.key_id,
        key_digest=key.evidence_digest,
        signing_purpose=signing_purpose,
        signed_at=signed_at,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )


def verify_signed_envelope(
    artifact: Any,
    envelope: SignedGovernanceEnvelope,
    registry: SigningKeyRegistry,
    *,
    institution_id: str,
    model_id: str,
    version_id: str | None,
    artifact_type: str,
    signing_purpose: str,
    at_time: int | None = None,
) -> str:
    if envelope.institution_id != institution_id or envelope.model_id != model_id:
        raise GovernanceError("signed envelope is bound to different institution/model scope")
    if envelope.version_id != version_id:
        raise GovernanceError("signed envelope is bound to different model-version scope")
    if envelope.artifact_type != artifact_type or envelope.signing_purpose != signing_purpose:
        raise GovernanceError("signed envelope has different artifact type or signing purpose")
    if envelope.artifact_digest != sha256_digest(artifact):
        raise GovernanceError("signed envelope artifact digest does not match exact artifact payload")

    key = registry.key(envelope.institution_id, envelope.key_id)
    if key.evidence_digest != envelope.key_digest:
        raise GovernanceError("signed envelope is bound to different verification-key content")
    if key.owner_id != envelope.signer_id:
        raise GovernanceError("signed envelope signer does not own the registered verification key")
    if envelope.signer_role not in key.permitted_roles:
        raise GovernanceError("signed envelope signer role is outside registered key scope")

    # Historical validity is always checked at signing time. Current-use callers may
    # additionally require the key to remain active at a later evaluation time.
    registry.assert_key_active(key, at_time=envelope.signed_at)
    if at_time is not None:
        registry.assert_key_active(key, at_time=at_time)

    payload = _signature_payload(
        artifact,
        institution_id=envelope.institution_id,
        model_id=envelope.model_id,
        version_id=envelope.version_id,
        artifact_type=envelope.artifact_type,
        signer_id=envelope.signer_id,
        signer_role=envelope.signer_role,
        key_id=envelope.key_id,
        key_digest=envelope.key_digest,
        signing_purpose=envelope.signing_purpose,
        signed_at=envelope.signed_at,
    )
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_b64("public_key_base64", key.public_key_base64, expected_length=32)
        ).verify(
            _decode_b64("signature_base64", envelope.signature_base64, expected_length=64),
            payload,
        )
    except InvalidSignature as exc:
        raise GovernanceError("invalid Ed25519 governance signature") from exc
    return envelope.evidence_digest
