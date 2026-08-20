from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import re
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, sha256_digest
from .models import GovernanceError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SQL_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_SESSION_SETTING = re.compile(r"^modelriskops\.[a-z_][a-z0-9_]{0,62}$")


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str | None, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _positive(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _SQL_IDENTIFIER.fullmatch(value):
        raise GovernanceError(f"{name} must be a safe lowercase PostgreSQL identifier")
    return value


def _setting(name: str, value: str) -> str:
    if not isinstance(value, str) or not _SESSION_SETTING.fullmatch(value):
        raise GovernanceError(f"{name} must be a modelriskops.* PostgreSQL session setting")
    return value


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise GovernanceError("base64url values must be non-empty unpadded text")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover
        raise GovernanceError("invalid base64url value") from exc


def _sorted_digests(name: str, values: tuple[str, ...], *, allow_empty: bool = False) -> tuple[str, ...]:
    if not allow_empty and not values:
        raise GovernanceError(f"{name} must not be empty")
    for value in values:
        _digest(name, value)
    if len(values) != len(set(values)) or tuple(sorted(values)) != values:
        raise GovernanceError(f"{name} must be unique and canonically sorted")
    return values


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class TenantEnvironment(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class CryptoKeyPurpose(str, Enum):
    CONFIG_SIGNING = "config_signing"
    EVIDENCE_ENCRYPTION = "evidence_encryption"


class CryptoKeyCustody(str, Enum):
    KMS = "kms"
    HSM = "hsm"


class CryptoKeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    DISABLED = "disabled"


class CryptoAlgorithm(str, Enum):
    ED25519 = "Ed25519"
    AES_256_GCM = "AES-256-GCM"


@dataclass(frozen=True, slots=True)
class PostgresRlsPolicy:
    institution_id: str
    policy_id: str
    policy_version: int
    table_name: str
    policy_name: str
    institution_column: str
    tenant_column: str
    institution_setting: str
    tenant_setting: str
    force_row_level_security: bool
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "policy_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("policy_version", self.policy_version)
        for name in ("table_name", "policy_name", "institution_column", "tenant_column"):
            _identifier(name, getattr(self, name))
        _setting("institution_setting", self.institution_setting)
        _setting("tenant_setting", self.tenant_setting)
        if self.institution_setting == self.tenant_setting:
            raise GovernanceError("institution and tenant session settings must be distinct")
        if self.institution_column == self.tenant_column:
            raise GovernanceError("institution and tenant RLS columns must be distinct")
        if self.force_row_level_security is not True:
            raise GovernanceError("v0.7 RLS reference policies must force row level security")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def render_postgres_rls_sql(policy: PostgresRlsPolicy) -> str:
    if not isinstance(policy, PostgresRlsPolicy):
        raise GovernanceError("RLS renderer requires a PostgresRlsPolicy")
    predicate = (
        f"{policy.institution_column} = current_setting('{policy.institution_setting}', true) "
        f"AND {policy.tenant_column} = current_setting('{policy.tenant_setting}', true)"
    )
    return "\n".join((
        f"ALTER TABLE {policy.table_name} ENABLE ROW LEVEL SECURITY;",
        f"ALTER TABLE {policy.table_name} FORCE ROW LEVEL SECURITY;",
        f"CREATE POLICY {policy.policy_name} ON {policy.table_name}",
        f"USING ({predicate})",
        f"WITH CHECK ({predicate});",
    ))


@dataclass(frozen=True, slots=True)
class TenantIsolationProfile:
    institution_id: str
    tenant_id: str
    profile_version: int
    environment: TenantEnvironment
    database_role: str
    namespace_digest: str
    rls_policy_digests: tuple[str, ...]
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("profile_version", self.profile_version)
        if not isinstance(self.environment, TenantEnvironment):
            raise GovernanceError("tenant environment must be governed")
        _identifier("database_role", self.database_role)
        _digest("namespace_digest", self.namespace_digest)
        object.__setattr__(self, "rls_policy_digests", _sorted_digests("rls_policy_digests", self.rls_policy_digests))
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class TenantIsolationRegistry:
    """Append-only tenant-isolation metadata. It never connects to PostgreSQL or proves deployed RLS."""

    def __init__(self) -> None:
        self._policies: dict[tuple[str, str, int], PostgresRlsPolicy] = {}
        self._profiles: dict[tuple[str, str, int], TenantIsolationProfile] = {}

    def policy_history(self, institution_id: str, policy_id: str) -> tuple[PostgresRlsPolicy, ...]:
        return tuple(sorted(
            (item for (scope, candidate, _), item in self._policies.items() if scope == institution_id and candidate == policy_id),
            key=lambda item: item.policy_version,
        ))

    def register_policy(self, policy: PostgresRlsPolicy) -> str:
        identity = (policy.institution_id, policy.policy_id, policy.policy_version)
        existing = self._policies.get(identity)
        if existing is not None:
            if existing.evidence_digest != policy.evidence_digest:
                raise GovernanceError("RLS policy identity/version already exists with different content")
            return existing.evidence_digest
        history = self.policy_history(policy.institution_id, policy.policy_id)
        expected = 1 if not history else history[-1].policy_version + 1
        if policy.policy_version != expected:
            raise GovernanceError(f"RLS policy versions must be contiguous; expected version {expected}")
        if history and policy.registered_at < history[-1].registered_at:
            raise GovernanceError("new RLS policy cannot predate the previous version")
        self._policies[identity] = policy
        return policy.evidence_digest

    def _policy_by_digest(self, institution_id: str, digest: str) -> PostgresRlsPolicy:
        for (scope, _, _), policy in self._policies.items():
            if scope == institution_id and policy.evidence_digest == digest:
                return policy
        raise GovernanceError("unknown PostgreSQL RLS policy digest")

    def assert_policy_current(self, policy: PostgresRlsPolicy) -> None:
        history = self.policy_history(policy.institution_id, policy.policy_id)
        if not history or history[-1].evidence_digest != policy.evidence_digest:
            raise GovernanceError("RLS policy is stale")

    def profile_history(self, institution_id: str, tenant_id: str) -> tuple[TenantIsolationProfile, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._profiles.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: item.profile_version,
        ))

    def register_profile(self, profile: TenantIsolationProfile) -> str:
        identity = (profile.institution_id, profile.tenant_id, profile.profile_version)
        existing = self._profiles.get(identity)
        if existing is not None:
            if existing.evidence_digest != profile.evidence_digest:
                raise GovernanceError("tenant isolation profile identity/version already exists with different content")
            return existing.evidence_digest
        for digest in profile.rls_policy_digests:
            policy = self._policy_by_digest(profile.institution_id, digest)
            self.assert_policy_current(policy)
            if policy.registered_at > profile.registered_at:
                raise GovernanceError("tenant isolation profile cannot bind future RLS evidence")
        history = self.profile_history(profile.institution_id, profile.tenant_id)
        expected = 1 if not history else history[-1].profile_version + 1
        if profile.profile_version != expected:
            raise GovernanceError(f"tenant isolation profile versions must be contiguous; expected version {expected}")
        if history and profile.registered_at < history[-1].registered_at:
            raise GovernanceError("new tenant isolation profile cannot predate the previous version")
        self._profiles[identity] = profile
        return profile.evidence_digest

    def current_profile(self, institution_id: str, tenant_id: str) -> TenantIsolationProfile:
        history = self.profile_history(institution_id, tenant_id)
        if not history:
            raise GovernanceError("tenant isolation profile is not registered")
        return history[-1]

    def assert_profile_current(self, profile: TenantIsolationProfile) -> None:
        current = self.current_profile(profile.institution_id, profile.tenant_id)
        if current.evidence_digest != profile.evidence_digest:
            raise GovernanceError("tenant isolation profile is stale")
        for digest in profile.rls_policy_digests:
            self.assert_policy_current(self._policy_by_digest(profile.institution_id, digest))

    def snapshot_digest(self, institution_id: str, tenant_id: str) -> str:
        profile = self.current_profile(institution_id, tenant_id)
        self.assert_profile_current(profile)
        return sha256_digest({
            "institution_id": institution_id,
            "tenant_id": tenant_id,
            "profile_digest": profile.evidence_digest,
            "rls_policy_digests": profile.rls_policy_digests,
        })


@dataclass(frozen=True, slots=True)
class InstitutionCryptoKeyReference:
    institution_id: str
    tenant_id: str
    purpose: CryptoKeyPurpose
    key_version: int
    key_id: str
    custody: CryptoKeyCustody
    algorithm: CryptoAlgorithm
    public_key_base64url: str | None
    not_before: int
    not_after: int
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id", "key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.purpose, CryptoKeyPurpose):
            raise GovernanceError("crypto key purpose must be governed")
        _positive("key_version", self.key_version)
        if not isinstance(self.custody, CryptoKeyCustody):
            raise GovernanceError("crypto key custody must be KMS or HSM")
        if not isinstance(self.algorithm, CryptoAlgorithm):
            raise GovernanceError("crypto key algorithm must be governed")
        if self.purpose is CryptoKeyPurpose.CONFIG_SIGNING:
            if self.algorithm is not CryptoAlgorithm.ED25519:
                raise GovernanceError("configuration signing keys must use Ed25519")
            if self.public_key_base64url is None or len(_decode(self.public_key_base64url)) != 32:
                raise GovernanceError("Ed25519 configuration signing keys require a 32-byte public key")
        else:
            if self.algorithm is not CryptoAlgorithm.AES_256_GCM:
                raise GovernanceError("evidence encryption keys must use AES-256-GCM")
            if self.public_key_base64url is not None:
                raise GovernanceError("symmetric KMS/HSM key material must not be embedded")
        for name in ("not_before", "not_after", "registered_at"):
            _timestamp(name, getattr(self, name))
        if self.not_after <= self.not_before:
            raise GovernanceError("key not_after must be after not_before")
        if self.registered_at > self.not_after:
            raise GovernanceError("key registration cannot occur after key expiry")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class CryptoKeyLifecycleState:
    institution_id: str
    tenant_id: str
    purpose: CryptoKeyPurpose
    key_reference_digest: str
    state_version: int
    status: CryptoKeyStatus
    effective_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "tenant_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.purpose, CryptoKeyPurpose):
            raise GovernanceError("lifecycle key purpose must be governed")
        _digest("key_reference_digest", self.key_reference_digest)
        _positive("state_version", self.state_version)
        if not isinstance(self.status, CryptoKeyStatus):
            raise GovernanceError("lifecycle status must be governed")
        _timestamp("effective_at", self.effective_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


_ALLOWED_KEY_TRANSITIONS = {
    CryptoKeyStatus.ACTIVE: frozenset({CryptoKeyStatus.RETIRED, CryptoKeyStatus.DISABLED}),
    CryptoKeyStatus.RETIRED: frozenset({CryptoKeyStatus.DISABLED}),
    CryptoKeyStatus.DISABLED: frozenset(),
}


class InstitutionCryptoKeyRegistry:
    """Append-only KMS/HSM key references and lifecycle states; it stores no private or symmetric key bytes."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str, CryptoKeyPurpose, int], InstitutionCryptoKeyReference] = {}
        self._states: dict[tuple[str, str, str, int], CryptoKeyLifecycleState] = {}

    def history(self, institution_id: str, tenant_id: str, purpose: CryptoKeyPurpose) -> tuple[InstitutionCryptoKeyReference, ...]:
        return tuple(sorted(
            (item for (scope, tenant, candidate_purpose, _), item in self._keys.items() if scope == institution_id and tenant == tenant_id and candidate_purpose is purpose),
            key=lambda item: item.key_version,
        ))

    def register(self, key: InstitutionCryptoKeyReference) -> str:
        identity = (key.institution_id, key.tenant_id, key.purpose, key.key_version)
        existing = self._keys.get(identity)
        if existing is not None:
            if existing.evidence_digest != key.evidence_digest:
                raise GovernanceError("crypto key purpose/version already exists with different content")
            return existing.evidence_digest
        history = self.history(key.institution_id, key.tenant_id, key.purpose)
        expected = 1 if not history else history[-1].key_version + 1
        if key.key_version != expected:
            raise GovernanceError(f"crypto key versions must be contiguous; expected version {expected}")
        if history and key.registered_at < history[-1].registered_at:
            raise GovernanceError("new crypto key reference cannot predate the previous version")
        if any(item.key_id == key.key_id for item in history):
            raise GovernanceError("rotated key versions must use distinct key_id values")
        self._keys[identity] = key
        initial = CryptoKeyLifecycleState(
            institution_id=key.institution_id,
            tenant_id=key.tenant_id,
            purpose=key.purpose,
            key_reference_digest=key.evidence_digest,
            state_version=1,
            status=CryptoKeyStatus.ACTIVE,
            effective_at=key.registered_at,
        )
        self._states[(key.institution_id, key.tenant_id, key.evidence_digest, 1)] = initial
        return key.evidence_digest

    def by_digest(self, institution_id: str, tenant_id: str, digest: str) -> InstitutionCryptoKeyReference:
        for (scope, tenant, _, _), key in self._keys.items():
            if scope == institution_id and tenant == tenant_id and key.evidence_digest == digest:
                return key
        raise GovernanceError("unknown tenant crypto key reference digest")

    def lifecycle(self, key: InstitutionCryptoKeyReference) -> tuple[CryptoKeyLifecycleState, ...]:
        return tuple(sorted(
            (item for (scope, tenant, digest, _), item in self._states.items() if scope == key.institution_id and tenant == key.tenant_id and digest == key.evidence_digest),
            key=lambda item: item.state_version,
        ))

    def transition(self, state: CryptoKeyLifecycleState) -> str:
        key = self.by_digest(state.institution_id, state.tenant_id, state.key_reference_digest)
        if state.purpose is not key.purpose:
            raise GovernanceError("key lifecycle purpose does not match key reference")
        identity = (state.institution_id, state.tenant_id, state.key_reference_digest, state.state_version)
        existing = self._states.get(identity)
        if existing is not None:
            if existing.evidence_digest != state.evidence_digest:
                raise GovernanceError("key lifecycle state version already exists with different content")
            return existing.evidence_digest
        history = self.lifecycle(key)
        expected = history[-1].state_version + 1
        if state.state_version != expected:
            raise GovernanceError(f"key lifecycle state versions must be contiguous; expected version {expected}")
        previous = history[-1]
        if state.status not in _ALLOWED_KEY_TRANSITIONS[previous.status]:
            raise GovernanceError(f"unsupported key lifecycle transition: {previous.status.value} -> {state.status.value}")
        if state.effective_at < previous.effective_at:
            raise GovernanceError("key lifecycle cannot move backward in time")
        self._states[identity] = state
        return state.evidence_digest

    def status_at(self, key: InstitutionCryptoKeyReference, *, at: int) -> CryptoKeyStatus:
        _timestamp("at", at)
        eligible = [state for state in self.lifecycle(key) if state.effective_at <= at]
        if not eligible:
            raise GovernanceError("key has no lifecycle state effective at requested time")
        return eligible[-1].status

    def current_key(self, institution_id: str, tenant_id: str, purpose: CryptoKeyPurpose, *, now: int) -> InstitutionCryptoKeyReference:
        candidates = [
            key for key in self.history(institution_id, tenant_id, purpose)
            if key.not_before <= now < key.not_after and self.status_at(key, at=now) is CryptoKeyStatus.ACTIVE
        ]
        if not candidates:
            raise GovernanceError("no active tenant crypto key exists for requested purpose/time")
        return candidates[-1]

    def assert_new_operation_allowed(self, key: InstitutionCryptoKeyReference, *, artifact_time: int, now: int) -> None:
        _timestamp("artifact_time", artifact_time)
        _timestamp("now", now)
        if artifact_time != now:
            raise GovernanceError("new cryptographic artifact time must equal current operation time")
        current = self.current_key(key.institution_id, key.tenant_id, key.purpose, now=now)
        if current.evidence_digest != key.evidence_digest:
            raise GovernanceError("new cryptographic operations require the current active key")


@dataclass(frozen=True, slots=True)
class ConfigurationChangeRequest:
    change_id: str
    institution_id: str
    tenant_id: str
    sequence: int
    object_type: str
    object_id: str
    previous_configuration_digest: str | None
    proposed_configuration_digest: str
    change_reason_digest: str
    requested_by_human_id: str
    requested_at: int
    effective_at: int

    def __post_init__(self) -> None:
        for name in ("change_id", "institution_id", "tenant_id", "object_type", "object_id", "requested_by_human_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive("sequence", self.sequence)
        _digest("previous_configuration_digest", self.previous_configuration_digest, optional=True)
        _digest("proposed_configuration_digest", self.proposed_configuration_digest)
        _digest("change_reason_digest", self.change_reason_digest)
        if self.previous_configuration_digest == self.proposed_configuration_digest:
            raise GovernanceError("configuration change must alter the represented configuration digest")
        _timestamp("requested_at", self.requested_at)
        _timestamp("effective_at", self.effective_at)
        if self.effective_at < self.requested_at:
            raise GovernanceError("configuration change effective_at cannot predate requested_at")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class SignedConfigurationChange:
    request: ConfigurationChangeRequest
    previous_change_digest: str | None
    key_reference_digest: str
    key_id: str
    key_version: int
    algorithm: str
    signed_at: int
    signature_base64url: str
    signing_document_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, ConfigurationChangeRequest):
            raise GovernanceError("signed configuration change requires a ConfigurationChangeRequest")
        _digest("previous_change_digest", self.previous_change_digest, optional=True)
        if self.request.sequence == 1 and self.previous_change_digest is not None:
            raise GovernanceError("first configuration change must not have a previous change digest")
        if self.request.sequence > 1 and self.previous_change_digest is None:
            raise GovernanceError("subsequent configuration changes require a previous change digest")
        _digest("key_reference_digest", self.key_reference_digest)
        _text("key_id", self.key_id)
        _positive("key_version", self.key_version)
        if self.algorithm != CryptoAlgorithm.ED25519.value:
            raise GovernanceError("signed configuration changes require Ed25519")
        _timestamp("signed_at", self.signed_at)
        if len(_decode(self.signature_base64url)) != 64:
            raise GovernanceError("Ed25519 configuration signature must decode to 64 bytes")
        _digest("signing_document_digest", self.signing_document_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class ConfigurationChangeSigner(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str
    def sign(self, message: bytes) -> bytes: ...


def configuration_change_signing_document(request: ConfigurationChangeRequest, *, previous_change_digest: str | None, key_reference_digest: str, key_id: str, key_version: int, signed_at: int) -> dict[str, object]:
    return {
        "purpose": "modelriskops.configuration-change.v1",
        "institution_id": request.institution_id,
        "tenant_id": request.tenant_id,
        "sequence": request.sequence,
        "request_digest": request.evidence_digest,
        "previous_change_digest": previous_change_digest,
        "key_reference_digest": key_reference_digest,
        "key_id": key_id,
        "key_version": key_version,
        "algorithm": CryptoAlgorithm.ED25519.value,
        "signed_at": signed_at,
    }


def sign_configuration_change(request: ConfigurationChangeRequest, *, previous_change_digest: str | None, key_reference: InstitutionCryptoKeyReference, key_registry: InstitutionCryptoKeyRegistry, signer: ConfigurationChangeSigner, signed_at: int, now: int) -> SignedConfigurationChange:
    registered = key_registry.by_digest(request.institution_id, request.tenant_id, key_reference.evidence_digest)
    if registered.evidence_digest != key_reference.evidence_digest:
        raise GovernanceError("configuration signing key reference mismatch")
    if key_reference.purpose is not CryptoKeyPurpose.CONFIG_SIGNING:
        raise GovernanceError("configuration changes require a configuration-signing key")
    if signer.institution_id != request.institution_id or signer.tenant_id != request.tenant_id:
        raise GovernanceError("configuration signer tenant scope mismatch")
    if signer.key_id != key_reference.key_id or signer.key_version != key_reference.key_version or signer.algorithm != CryptoAlgorithm.ED25519.value:
        raise GovernanceError("configuration signer does not match exact key reference")
    if signed_at < request.requested_at or signed_at > request.effective_at:
        raise GovernanceError("configuration signature must occur between request and effective time")
    key_registry.assert_new_operation_allowed(key_reference, artifact_time=signed_at, now=now)
    document = configuration_change_signing_document(
        request,
        previous_change_digest=previous_change_digest,
        key_reference_digest=key_reference.evidence_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        signed_at=signed_at,
    )
    signature = signer.sign(canonical_json(document).encode("utf-8"))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise GovernanceError("Ed25519 configuration signer must return a 64-byte signature")
    return SignedConfigurationChange(
        request=request,
        previous_change_digest=previous_change_digest,
        key_reference_digest=key_reference.evidence_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        algorithm=CryptoAlgorithm.ED25519.value,
        signed_at=signed_at,
        signature_base64url=_encode(signature),
        signing_document_digest=sha256_digest(document),
    )


def verify_signed_configuration_change(signed: SignedConfigurationChange, *, key_registry: InstitutionCryptoKeyRegistry, now: int) -> ConfigurationChangeRequest:
    _timestamp("now", now)
    if signed.signed_at > now:
        raise GovernanceError("configuration change signature cannot be from the future")
    key = key_registry.by_digest(signed.request.institution_id, signed.request.tenant_id, signed.key_reference_digest)
    if key.purpose is not CryptoKeyPurpose.CONFIG_SIGNING:
        raise GovernanceError("configuration signature key purpose mismatch")
    if key.key_id != signed.key_id or key.key_version != signed.key_version:
        raise GovernanceError("configuration signature key identity mismatch")
    if key_registry.status_at(key, at=signed.signed_at) is not CryptoKeyStatus.ACTIVE:
        raise GovernanceError("configuration signing key was not active at signature time")
    if not (key.not_before <= signed.signed_at < key.not_after):
        raise GovernanceError("configuration signing key was not valid at signature time")
    document = configuration_change_signing_document(
        signed.request,
        previous_change_digest=signed.previous_change_digest,
        key_reference_digest=signed.key_reference_digest,
        key_id=signed.key_id,
        key_version=signed.key_version,
        signed_at=signed.signed_at,
    )
    if sha256_digest(document) != signed.signing_document_digest:
        raise GovernanceError("configuration signing document digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode(key.public_key_base64url or ""))
        public_key.verify(_decode(signed.signature_base64url), canonical_json(document).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise GovernanceError("configuration change signature is invalid") from exc
    return signed.request


class ConfigurationChangeRegistry:
    """Append-only tenant configuration chain; no configuration is applied to external systems."""

    def __init__(self) -> None:
        self._changes: dict[tuple[str, str, int], SignedConfigurationChange] = {}
        self._latest_object_digest: dict[tuple[str, str, str, str], str] = {}

    def history(self, institution_id: str, tenant_id: str) -> tuple[SignedConfigurationChange, ...]:
        return tuple(sorted(
            (item for (scope, tenant, _), item in self._changes.items() if scope == institution_id and tenant == tenant_id),
            key=lambda item: item.request.sequence,
        ))

    def append(self, signed: SignedConfigurationChange, *, key_registry: InstitutionCryptoKeyRegistry, now: int) -> str:
        request = signed.request
        identity = (request.institution_id, request.tenant_id, request.sequence)
        existing = self._changes.get(identity)
        if existing is not None:
            if existing.evidence_digest != signed.evidence_digest:
                raise GovernanceError("configuration change sequence already exists with different content")
            return existing.evidence_digest
        verify_signed_configuration_change(signed, key_registry=key_registry, now=now)
        if now < request.effective_at:
            raise GovernanceError("configuration change cannot become current before effective_at")
        history = self.history(request.institution_id, request.tenant_id)
        expected = 1 if not history else history[-1].request.sequence + 1
        if request.sequence != expected:
            raise GovernanceError(f"configuration change sequence must be contiguous; expected {expected}")
        expected_previous = None if not history else history[-1].evidence_digest
        if signed.previous_change_digest != expected_previous:
            raise GovernanceError("configuration change does not extend the exact tenant change chain")
        if history and signed.signed_at < history[-1].signed_at:
            raise GovernanceError("configuration change chain cannot move backward in time")
        object_key = (request.institution_id, request.tenant_id, request.object_type, request.object_id)
        current_digest = self._latest_object_digest.get(object_key)
        if current_digest is None:
            if request.previous_configuration_digest is not None:
                raise GovernanceError("first configuration change for an object must not claim previous state")
        elif request.previous_configuration_digest != current_digest:
            raise GovernanceError("configuration change previous digest does not match current object state")
        self._changes[identity] = signed
        self._latest_object_digest[object_key] = request.proposed_configuration_digest
        return signed.evidence_digest


@dataclass(frozen=True, slots=True)
class EncryptedGovernanceEvidence:
    envelope_id: str
    institution_id: str
    tenant_id: str
    isolation_profile_digest: str
    key_reference_digest: str
    key_id: str
    key_version: int
    algorithm: str
    subject_artifact_digest: str
    plaintext_digest: str
    aad_digest: str
    nonce_base64url: str
    ciphertext_base64url: str
    encrypted_at: int

    def __post_init__(self) -> None:
        for name in ("envelope_id", "institution_id", "tenant_id", "key_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("isolation_profile_digest", "key_reference_digest", "subject_artifact_digest", "plaintext_digest", "aad_digest"):
            _digest(name, getattr(self, name))
        _positive("key_version", self.key_version)
        if self.algorithm != CryptoAlgorithm.AES_256_GCM.value:
            raise GovernanceError("tenant governance evidence must use AES-256-GCM")
        if len(_decode(self.nonce_base64url)) != 12:
            raise GovernanceError("AES-256-GCM nonce must decode to 12 bytes")
        if len(_decode(self.ciphertext_base64url)) < 16:
            raise GovernanceError("AES-256-GCM ciphertext must contain an authentication tag")
        _timestamp("encrypted_at", self.encrypted_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class TenantEvidenceEncryptor(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str
    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...


class TenantEvidenceDecryptor(Protocol):
    institution_id: str
    tenant_id: str
    key_id: str
    key_version: int
    algorithm: str
    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


def encrypted_evidence_aad_document(*, envelope_id: str, institution_id: str, tenant_id: str, isolation_profile_digest: str, key_reference_digest: str, subject_artifact_digest: str) -> dict[str, str]:
    return {
        "purpose": "modelriskops.tenant-encrypted-governance-evidence.v1",
        "envelope_id": envelope_id,
        "institution_id": institution_id,
        "tenant_id": tenant_id,
        "isolation_profile_digest": isolation_profile_digest,
        "key_reference_digest": key_reference_digest,
        "subject_artifact_digest": subject_artifact_digest,
    }


def encrypt_governance_evidence(plaintext: bytes, *, envelope_id: str, institution_id: str, tenant_id: str, subject_artifact_digest: str, isolation_profile: TenantIsolationProfile, isolation_registry: TenantIsolationRegistry, key_reference: InstitutionCryptoKeyReference, key_registry: InstitutionCryptoKeyRegistry, encryptor: TenantEvidenceEncryptor, encrypted_at: int, now: int) -> EncryptedGovernanceEvidence:
    if not isinstance(plaintext, bytes) or not plaintext:
        raise GovernanceError("governance evidence plaintext must be non-empty bytes")
    _digest("subject_artifact_digest", subject_artifact_digest)
    if isolation_profile.institution_id != institution_id or isolation_profile.tenant_id != tenant_id:
        raise GovernanceError("tenant isolation profile scope mismatch")
    isolation_registry.assert_profile_current(isolation_profile)
    registered = key_registry.by_digest(institution_id, tenant_id, key_reference.evidence_digest)
    if registered.evidence_digest != key_reference.evidence_digest:
        raise GovernanceError("evidence encryption key reference mismatch")
    if key_reference.purpose is not CryptoKeyPurpose.EVIDENCE_ENCRYPTION:
        raise GovernanceError("governance evidence requires an evidence-encryption key")
    key_registry.assert_new_operation_allowed(key_reference, artifact_time=encrypted_at, now=now)
    if encryptor.institution_id != institution_id or encryptor.tenant_id != tenant_id or encryptor.key_id != key_reference.key_id or encryptor.key_version != key_reference.key_version or encryptor.algorithm != CryptoAlgorithm.AES_256_GCM.value:
        raise GovernanceError("evidence encryptor does not match exact tenant key reference")
    nonce = secrets.token_bytes(12)
    aad_document = encrypted_evidence_aad_document(
        envelope_id=envelope_id,
        institution_id=institution_id,
        tenant_id=tenant_id,
        isolation_profile_digest=isolation_profile.evidence_digest,
        key_reference_digest=key_reference.evidence_digest,
        subject_artifact_digest=subject_artifact_digest,
    )
    aad = canonical_json(aad_document).encode("utf-8")
    ciphertext = encryptor.encrypt(nonce, plaintext, aad)
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise GovernanceError("AES-256-GCM encryptor must return ciphertext with authentication tag")
    return EncryptedGovernanceEvidence(
        envelope_id=envelope_id,
        institution_id=institution_id,
        tenant_id=tenant_id,
        isolation_profile_digest=isolation_profile.evidence_digest,
        key_reference_digest=key_reference.evidence_digest,
        key_id=key_reference.key_id,
        key_version=key_reference.key_version,
        algorithm=CryptoAlgorithm.AES_256_GCM.value,
        subject_artifact_digest=subject_artifact_digest,
        plaintext_digest=_sha256_bytes(plaintext),
        aad_digest=_sha256_bytes(aad),
        nonce_base64url=_encode(nonce),
        ciphertext_base64url=_encode(ciphertext),
        encrypted_at=encrypted_at,
    )


def decrypt_governance_evidence(envelope: EncryptedGovernanceEvidence, *, isolation_registry: TenantIsolationRegistry, key_registry: InstitutionCryptoKeyRegistry, decryptor: TenantEvidenceDecryptor, now: int) -> bytes:
    _timestamp("now", now)
    profile = isolation_registry.current_profile(envelope.institution_id, envelope.tenant_id)
    if profile.evidence_digest != envelope.isolation_profile_digest:
        raise GovernanceError("encrypted evidence isolation profile is not current")
    isolation_registry.assert_profile_current(profile)
    key = key_registry.by_digest(envelope.institution_id, envelope.tenant_id, envelope.key_reference_digest)
    if key.key_id != envelope.key_id or key.key_version != envelope.key_version or key.purpose is not CryptoKeyPurpose.EVIDENCE_ENCRYPTION:
        raise GovernanceError("encrypted evidence key identity mismatch")
    if key_registry.status_at(key, at=now) is CryptoKeyStatus.DISABLED:
        raise GovernanceError("disabled evidence-encryption key cannot decrypt evidence")
    if decryptor.institution_id != envelope.institution_id or decryptor.tenant_id != envelope.tenant_id or decryptor.key_id != envelope.key_id or decryptor.key_version != envelope.key_version or decryptor.algorithm != CryptoAlgorithm.AES_256_GCM.value:
        raise GovernanceError("evidence decryptor does not match exact tenant key reference")
    aad_document = encrypted_evidence_aad_document(
        envelope_id=envelope.envelope_id,
        institution_id=envelope.institution_id,
        tenant_id=envelope.tenant_id,
        isolation_profile_digest=envelope.isolation_profile_digest,
        key_reference_digest=envelope.key_reference_digest,
        subject_artifact_digest=envelope.subject_artifact_digest,
    )
    aad = canonical_json(aad_document).encode("utf-8")
    if _sha256_bytes(aad) != envelope.aad_digest:
        raise GovernanceError("encrypted evidence AAD digest mismatch")
    try:
        plaintext = decryptor.decrypt(_decode(envelope.nonce_base64url), _decode(envelope.ciphertext_base64url), aad)
    except Exception as exc:
        raise GovernanceError("encrypted governance evidence authentication failed") from exc
    if not isinstance(plaintext, bytes) or _sha256_bytes(plaintext) != envelope.plaintext_digest:
        raise GovernanceError("decrypted governance evidence digest mismatch")
    return plaintext
