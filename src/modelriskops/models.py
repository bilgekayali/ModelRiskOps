from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any


def _canonical(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _canonical(asdict(value))
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_artifact(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text(name: str, value: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty bounded text")


def _timestamp(name: str, value: str) -> None:
    _text(name, value, limit=64)
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be RFC3339 UTC")
    datetime.fromisoformat(value[:-1] + "+00:00")


class ModelFamily(str, Enum):
    STATISTICAL = "statistical"
    MACHINE_LEARNING = "machine_learning"
    GENERATIVE_AI = "generative_ai"
    RULE_BASED = "rule_based"
    OTHER = "other"


class LifecycleStatus(str, Enum):
    PROPOSED = "proposed"
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    APPROVED = "approved"
    PRODUCTION = "production"
    RESTRICTED = "restricted"
    RETIRED = "retired"


class RiskTier(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


_RISK_ORDER = {RiskTier.LOW: 0, RiskTier.MODERATE: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}


def max_risk(*tiers: RiskTier) -> RiskTier:
    return max(tiers, key=lambda value: _RISK_ORDER[value])


@dataclass(frozen=True, slots=True)
class ModelRecord:
    institution_id: str
    model_id: str
    name: str
    family: ModelFamily
    primary_use: str
    owner_id: str
    business_unit: str
    lifecycle_status: LifecycleStatus
    model_version: str
    production_use: bool
    registered_at: str
    schema_version: str = "modelriskops.model-record.v1"

    def __post_init__(self) -> None:
        for field in ("institution_id", "model_id", "name", "primary_use", "owner_id", "business_unit", "model_version", "schema_version"):
            _text(field, getattr(self, field), limit=512 if field == "primary_use" else 256)
        _timestamp("registered_at", self.registered_at)
        if self.lifecycle_status is LifecycleStatus.RETIRED and self.production_use:
            raise ValueError("retired model cannot be marked for production use")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ModelRiskAssessment:
    institution_id: str
    model_id: str
    impact_tier: RiskTier
    customer_decisioning: bool
    regulatory_reporting: bool
    generative_ai: bool
    external_dependency: bool
    personal_data: bool
    assessed_at: str
    schema_version: str = "modelriskops.model-risk-assessment.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        _text("model_id", self.model_id)
        _timestamp("assessed_at", self.assessed_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ClassificationPolicy:
    institution_id: str
    customer_decisioning_min_tier: RiskTier = RiskTier.HIGH
    regulatory_reporting_min_tier: RiskTier = RiskTier.HIGH
    generative_ai_min_tier: RiskTier = RiskTier.MODERATE
    external_dependency_min_tier: RiskTier = RiskTier.MODERATE
    personal_data_min_tier: RiskTier = RiskTier.MODERATE
    independent_validation_min_tier: RiskTier = RiskTier.HIGH
    schema_version: str = "modelriskops.classification-policy.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ModelClassification:
    institution_id: str
    model_id: str
    model_digest: str
    assessment_digest: str
    policy_digest: str
    risk_tier: RiskTier
    reason_codes: tuple[str, ...]
    independent_validation_required: bool
    classified_at: str
    schema_version: str = "modelriskops.model-classification.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        _text("model_id", self.model_id)
        for name in ("model_digest", "assessment_digest", "policy_digest"):
            value = getattr(self, name)
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not self.reason_codes or len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must be non-empty and unique")
        _timestamp("classified_at", self.classified_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)
