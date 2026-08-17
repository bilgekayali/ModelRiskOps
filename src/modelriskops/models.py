from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import re
from typing import Iterable

from .canonical import sha256_digest

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class GovernanceError(ValueError):
    """Raised when a governance contract fails closed."""


class LifecycleState(str, Enum):
    PROPOSED = "proposed"
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class ModelType(str, Enum):
    ANALYTICAL = "analytical"
    STATISTICAL = "statistical"
    MACHINE_LEARNING = "machine_learning"
    AI = "ai"
    GENERATIVE_AI = "generative_ai"
    VENDOR = "vendor"
    OTHER = "other"


class DependencyKind(str, Enum):
    DATASET = "dataset"
    SYSTEM = "system"
    VENDOR = "vendor"
    FOUNDATION_MODEL = "foundation_model"
    CRITICAL_SERVICE = "critical_service"
    OTHER = "other"


def _required_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _clean_tuple(name: str, values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(_required_text(name, value) for value in values)
    if len(result) != len(set(result)):
        raise GovernanceError(f"{name} must not contain duplicates")
    return result


@dataclass(frozen=True, slots=True)
class DependencyRef:
    kind: DependencyKind
    identifier: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", _required_text("dependency.identifier", self.identifier))
        object.__setattr__(self, "version", _required_text("dependency.version", self.version))
        object.__setattr__(self, "digest", _digest("dependency.digest", self.digest))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ModelRecord:
    institution_id: str
    model_id: str
    name: str
    owner_id: str
    business_use: str
    model_type: ModelType
    lifecycle_state: LifecycleState
    deployment_context: str
    intended_users: tuple[str, ...] = field(default_factory=tuple)
    prohibited_uses: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in (
            "institution_id",
            "model_id",
            "name",
            "owner_id",
            "business_use",
            "deployment_context",
        ):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        object.__setattr__(self, "intended_users", _clean_tuple("intended_users", self.intended_users))
        object.__setattr__(self, "prohibited_uses", _clean_tuple("prohibited_uses", self.prohibited_uses))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ModelVersion:
    institution_id: str
    model_id: str
    version_id: str
    artifact_digest: str
    code_digest: str
    data_digest: str
    config_digest: str
    provenance_source: str
    dependencies: tuple[DependencyRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "provenance_source"):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        for name in ("artifact_digest", "code_digest", "data_digest", "config_digest"):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))

        identities = [(dep.kind.value, dep.identifier, dep.version) for dep in self.dependencies]
        if len(identities) != len(set(identities)):
            raise GovernanceError("dependencies must not repeat the same kind/identifier/version")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


_ALLOWED_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.PROPOSED: frozenset({LifecycleState.DEVELOPMENT, LifecycleState.RETIRED}),
    LifecycleState.DEVELOPMENT: frozenset({LifecycleState.VALIDATION, LifecycleState.RETIRED}),
    LifecycleState.VALIDATION: frozenset({LifecycleState.DEVELOPMENT, LifecycleState.APPROVED, LifecycleState.RETIRED}),
    LifecycleState.APPROVED: frozenset({LifecycleState.DEPLOYED, LifecycleState.SUSPENDED, LifecycleState.RETIRED}),
    LifecycleState.DEPLOYED: frozenset({LifecycleState.SUSPENDED, LifecycleState.RETIRED}),
    LifecycleState.SUSPENDED: frozenset({LifecycleState.DEPLOYED, LifecycleState.RETIRED}),
    LifecycleState.RETIRED: frozenset(),
}


def transition_model(record: ModelRecord, target: LifecycleState) -> ModelRecord:
    if target == record.lifecycle_state:
        return record
    allowed = _ALLOWED_TRANSITIONS[record.lifecycle_state]
    if target not in allowed:
        raise GovernanceError(
            f"unsupported lifecycle transition: {record.lifecycle_state.value} -> {target.value}"
        )
    return replace(record, lifecycle_state=target)


class InventoryRegistry:
    """In-memory reference registry with immutable, digest-bound semantics."""

    def __init__(self) -> None:
        self._models: dict[tuple[str, str], ModelRecord] = {}
        self._versions: dict[tuple[str, str, str], ModelVersion] = {}

    def register_model(self, record: ModelRecord) -> str:
        key = (record.institution_id, record.model_id)
        existing = self._models.get(key)
        if existing is not None and existing.evidence_digest != record.evidence_digest:
            raise GovernanceError("model_id is already registered with different governance content")
        self._models.setdefault(key, record)
        return record.evidence_digest

    def register_version(self, version: ModelVersion) -> str:
        model_key = (version.institution_id, version.model_id)
        if model_key not in self._models:
            raise GovernanceError("model version cannot be registered before its model record")

        key = (version.institution_id, version.model_id, version.version_id)
        existing = self._versions.get(key)
        if existing is not None and existing.evidence_digest != version.evidence_digest:
            raise GovernanceError("version_id is already registered with different provenance")
        self._versions.setdefault(key, version)
        return version.evidence_digest

    def model(self, institution_id: str, model_id: str) -> ModelRecord:
        try:
            return self._models[(institution_id, model_id)]
        except KeyError as exc:
            raise GovernanceError("unknown model") from exc

    def version(self, institution_id: str, model_id: str, version_id: str) -> ModelVersion:
        try:
            return self._versions[(institution_id, model_id, version_id)]
        except KeyError as exc:
            raise GovernanceError("unknown model version") from exc

    def snapshot_digest(self) -> str:
        models = sorted(
            (record.evidence_digest for record in self._models.values())
        )
        versions = sorted(
            (version.evidence_digest for version in self._versions.values())
        )
        return sha256_digest({"models": models, "versions": versions})
