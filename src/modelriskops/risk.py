from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable

from .canonical import sha256_digest
from .models import GovernanceError, ModelRecord, ModelVersion


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FactorName(str, Enum):
    DECISION_IMPACT = "decision_impact"
    CUSTOMER_FINANCIAL_IMPACT = "customer_financial_impact"
    AUTONOMY = "autonomy"
    COMPLEXITY = "complexity"
    DATA_SENSITIVITY = "data_sensitivity"
    EXTERNAL_DEPENDENCY = "external_dependency"
    EXPLAINABILITY_NEED = "explainability_need"
    REGULATORY_RELEVANCE = "regulatory_relevance"
    DEPLOYMENT_CRITICALITY = "deployment_criticality"


class FactorLevel(IntEnum):
    LOW = 0
    MODERATE = 1
    HIGH = 2
    CRITICAL = 3


class ControlStrength(IntEnum):
    ABSENT = 0
    WEAK = 1
    ADEQUATE = 2
    STRONG = 3


@dataclass(frozen=True, slots=True)
class FactorWeight:
    factor: FactorName
    weight: int

    def __post_init__(self) -> None:
        if self.weight < 1 or self.weight > 5:
            raise GovernanceError("factor weight must be between 1 and 5")


@dataclass(frozen=True, slots=True)
class RiskFactor:
    factor: FactorName
    level: FactorLevel


@dataclass(frozen=True, slots=True)
class ControlObservation:
    control_id: str
    strength: ControlStrength
    evidence_digest: str

    def __post_init__(self) -> None:
        if not self.control_id.strip():
            raise GovernanceError("control_id must be non-empty")
        if len(self.evidence_digest) != 64 or any(ch not in "0123456789abcdef" for ch in self.evidence_digest):
            raise GovernanceError("control evidence_digest must be a lowercase SHA-256 hex digest")


@dataclass(frozen=True, slots=True)
class TierRequirementSet:
    tier: RiskTier
    requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        cleaned = tuple(item.strip() for item in self.requirements)
        if any(not item for item in cleaned):
            raise GovernanceError("risk requirements must be non-empty")
        if len(cleaned) != len(set(cleaned)):
            raise GovernanceError("risk requirements must not contain duplicates")
        object.__setattr__(self, "requirements", cleaned)


@dataclass(frozen=True, slots=True)
class RiskPolicyProfile:
    institution_id: str
    policy_id: str
    version: str
    weights: tuple[FactorWeight, ...]
    medium_threshold: int
    high_threshold: int
    critical_threshold: int
    max_control_credit: int
    requirement_sets: tuple[TierRequirementSet, ...]

    def __post_init__(self) -> None:
        for name in ("institution_id", "policy_id", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise GovernanceError(f"{name} must be a non-empty string")

        weight_factors = tuple(item.factor for item in self.weights)
        expected_factors = tuple(FactorName)
        if set(weight_factors) != set(expected_factors) or len(weight_factors) != len(expected_factors):
            raise GovernanceError("risk policy must define exactly one weight for every factor")

        if not (0 < self.medium_threshold < self.high_threshold < self.critical_threshold):
            raise GovernanceError("risk thresholds must be strictly increasing positive integers")
        if self.max_control_credit < 0:
            raise GovernanceError("max_control_credit must be non-negative")

        tiers = tuple(item.tier for item in self.requirement_sets)
        if set(tiers) != set(RiskTier) or len(tiers) != len(RiskTier):
            raise GovernanceError("risk policy must define exactly one requirement set per tier")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)

    def requirements_for(self, tier: RiskTier) -> tuple[str, ...]:
        for item in self.requirement_sets:
            if item.tier is tier:
                return item.requirements
        raise GovernanceError("missing requirement set for risk tier")


@dataclass(frozen=True, slots=True)
class FactorContribution:
    factor: FactorName
    level: FactorLevel
    weight: int
    points: int


@dataclass(frozen=True, slots=True)
class RiskDecision:
    institution_id: str
    model_id: str
    version_id: str
    model_digest: str
    model_version_digest: str
    policy_digest: str
    inherent_score: int
    inherent_tier: RiskTier
    control_credit: int
    residual_score: int
    residual_tier: RiskTier
    contributions: tuple[FactorContribution, ...]
    requirements: tuple[str, ...]

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def default_policy(institution_id: str = "default") -> RiskPolicyProfile:
    weights = tuple(
        FactorWeight(factor=factor, weight=weight)
        for factor, weight in (
            (FactorName.DECISION_IMPACT, 5),
            (FactorName.CUSTOMER_FINANCIAL_IMPACT, 5),
            (FactorName.AUTONOMY, 4),
            (FactorName.COMPLEXITY, 2),
            (FactorName.DATA_SENSITIVITY, 3),
            (FactorName.EXTERNAL_DEPENDENCY, 2),
            (FactorName.EXPLAINABILITY_NEED, 3),
            (FactorName.REGULATORY_RELEVANCE, 4),
            (FactorName.DEPLOYMENT_CRITICALITY, 4),
        )
    )
    requirement_sets = (
        TierRequirementSet(RiskTier.LOW, ("accountable_owner", "current_inventory")),
        TierRequirementSet(
            RiskTier.MEDIUM,
            ("accountable_owner", "current_inventory", "validation_plan", "monitoring_plan"),
        ),
        TierRequirementSet(
            RiskTier.HIGH,
            (
                "accountable_owner",
                "current_inventory",
                "independent_validation",
                "monitoring_plan",
                "change_control",
                "senior_risk_approval",
            ),
        ),
        TierRequirementSet(
            RiskTier.CRITICAL,
            (
                "accountable_owner",
                "current_inventory",
                "independent_validation",
                "enhanced_monitoring",
                "change_control",
                "senior_risk_approval",
                "executive_risk_acceptance",
                "contingency_plan",
            ),
        ),
    )
    return RiskPolicyProfile(
        institution_id=institution_id,
        policy_id="modelriskops-default-risk-policy",
        version="1",
        weights=weights,
        medium_threshold=24,
        high_threshold=48,
        critical_threshold=72,
        max_control_credit=12,
        requirement_sets=requirement_sets,
    )


def _tier(score: int, policy: RiskPolicyProfile) -> RiskTier:
    if score >= policy.critical_threshold:
        return RiskTier.CRITICAL
    if score >= policy.high_threshold:
        return RiskTier.HIGH
    if score >= policy.medium_threshold:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def _validate_factors(factors: Iterable[RiskFactor]) -> tuple[RiskFactor, ...]:
    result = tuple(factors)
    names = tuple(item.factor for item in result)
    if set(names) != set(FactorName) or len(names) != len(FactorName):
        raise GovernanceError("risk assessment must provide exactly one value for every required factor")
    return tuple(sorted(result, key=lambda item: item.factor.value))


def _validate_controls(controls: Iterable[ControlObservation]) -> tuple[ControlObservation, ...]:
    result = tuple(controls)
    ids = tuple(item.control_id for item in result)
    if len(ids) != len(set(ids)):
        raise GovernanceError("control observations must not repeat control_id")
    return tuple(sorted(result, key=lambda item: item.control_id))


def assess_model_risk(
    record: ModelRecord,
    version: ModelVersion,
    factors: Iterable[RiskFactor],
    controls: Iterable[ControlObservation],
    policy: RiskPolicyProfile,
) -> RiskDecision:
    if record.institution_id != version.institution_id or record.model_id != version.model_id:
        raise GovernanceError("model record and version identity do not match")
    if policy.institution_id not in {"default", record.institution_id}:
        raise GovernanceError("risk policy is not applicable to this institution")

    normalized_factors = _validate_factors(factors)
    normalized_controls = _validate_controls(controls)
    weights = {item.factor: item.weight for item in policy.weights}

    contributions = tuple(
        FactorContribution(
            factor=item.factor,
            level=item.level,
            weight=weights[item.factor],
            points=int(item.level) * weights[item.factor],
        )
        for item in normalized_factors
    )
    inherent_score = sum(item.points for item in contributions)
    inherent_tier = _tier(inherent_score, policy)

    raw_credit = sum(int(item.strength) for item in normalized_controls)
    control_credit = min(policy.max_control_credit, raw_credit)
    residual_score = max(0, inherent_score - control_credit)
    residual_tier = _tier(residual_score, policy)

    return RiskDecision(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        model_digest=record.evidence_digest,
        model_version_digest=version.evidence_digest,
        policy_digest=policy.evidence_digest,
        inherent_score=inherent_score,
        inherent_tier=inherent_tier,
        control_credit=control_credit,
        residual_score=residual_score,
        residual_tier=residual_tier,
        contributions=contributions,
        requirements=policy.requirements_for(residual_tier),
    )
