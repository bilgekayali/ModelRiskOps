from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .models import GovernanceError, InventoryRegistry
from .risk import RiskDecision, RiskTier


class DependencyMateriality(str, Enum):
    NON_MATERIAL = "non_material"
    MATERIAL = "material"
    CRITICAL = "critical"


class Substitutability(str, Enum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NONE = "none"


class DataAccessLevel(str, Enum):
    NONE = "none"
    NON_SENSITIVE = "non_sensitive"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"


class PortfolioAssessmentState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BREACHED = "breached"
    INCOMPLETE = "incomplete"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _positive_int(name: str, value: int, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GovernanceError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise GovernanceError(f"{name} must not exceed {maximum}")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _canonical_text_tuple(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_text(name, value) for value in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must not be empty")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must not contain duplicates")
    return tuple(sorted(cleaned))


def _canonical_digest_tuple(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_digest(name, value) for value in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must not be empty")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must not contain duplicates")
    return tuple(sorted(cleaned))


@dataclass(frozen=True, slots=True)
class ThirdPartyProviderProfile:
    institution_id: str
    provider_id: str
    profile_version: int
    legal_name: str
    accountable_owner_id: str
    service_jurisdictions: tuple[str, ...]
    due_diligence_evidence_digest: str
    contract_evidence_digest: str
    security_assurance_evidence_digest: str
    financial_resilience_evidence_digest: str
    due_diligence_expires_at: int
    contract_expires_at: int
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "provider_id", "legal_name", "accountable_owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("profile_version", self.profile_version)
        object.__setattr__(
            self,
            "service_jurisdictions",
            _canonical_text_tuple("service_jurisdictions", self.service_jurisdictions),
        )
        for name in (
            "due_diligence_evidence_digest",
            "contract_evidence_digest",
            "security_assurance_evidence_digest",
            "financial_resilience_evidence_digest",
        ):
            _digest(name, getattr(self, name))
        _timestamp("registered_at", self.registered_at)
        _timestamp("due_diligence_expires_at", self.due_diligence_expires_at)
        _timestamp("contract_expires_at", self.contract_expires_at)
        if self.due_diligence_expires_at <= self.registered_at:
            raise GovernanceError("provider due-diligence evidence must expire after registration")
        if self.contract_expires_at <= self.registered_at:
            raise GovernanceError("provider contract evidence must expire after registration")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyModelDependency:
    institution_id: str
    model_id: str
    version_id: str
    dependency_id: str
    dependency_version: int
    model_version_digest: str
    provider_id: str
    provider_profile_digest: str
    service_id: str
    service_description_digest: str
    materiality: DependencyMateriality
    substitutability: Substitutability
    data_access_level: DataAccessLevel
    registered_at: int

    def __post_init__(self) -> None:
        for name in (
            "institution_id",
            "model_id",
            "version_id",
            "dependency_id",
            "provider_id",
            "service_id",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("dependency_version", self.dependency_version)
        _digest("model_version_digest", self.model_version_digest)
        _digest("provider_profile_digest", self.provider_profile_digest)
        _digest("service_description_digest", self.service_description_digest)
        _timestamp("registered_at", self.registered_at)
        if not isinstance(self.materiality, DependencyMateriality):
            raise GovernanceError("dependency materiality must be governed")
        if not isinstance(self.substitutability, Substitutability):
            raise GovernanceError("dependency substitutability must be governed")
        if not isinstance(self.data_access_level, DataAccessLevel):
            raise GovernanceError("dependency data access level must be governed")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyExitPlan:
    institution_id: str
    model_id: str
    version_id: str
    dependency_id: str
    dependency_digest: str
    plan_version: int
    owner_id: str
    transition_strategy_digest: str
    portability_evidence_digest: str
    validation_plan_digest: str
    max_exit_seconds: int
    created_at: int
    tested_at: int | None = None
    test_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "dependency_id", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("dependency_digest", self.dependency_digest)
        _positive_int("plan_version", self.plan_version)
        for name in ("transition_strategy_digest", "portability_evidence_digest", "validation_plan_digest"):
            _digest(name, getattr(self, name))
        _positive_int("max_exit_seconds", self.max_exit_seconds, maximum=31536000)
        _timestamp("created_at", self.created_at)
        if (self.tested_at is None) != (self.test_evidence_digest is None):
            raise GovernanceError("exit-plan testing time and evidence digest must be supplied together")
        if self.tested_at is not None:
            _timestamp("tested_at", self.tested_at)
            if self.tested_at < self.created_at:
                raise GovernanceError("exit-plan test cannot predate plan creation")
            _digest("test_evidence_digest", self.test_evidence_digest or "")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PortfolioRiskPolicy:
    institution_id: str
    policy_id: str
    version: str
    single_provider_warning_bps: int
    single_provider_limit_bps: int
    high_critical_exposure_limit_bps: int
    require_exit_plan_for_material: bool
    require_tested_exit_for_critical: bool
    degrade_low_substitutability: bool

    def __post_init__(self) -> None:
        for name in ("institution_id", "policy_id", "version"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("single_provider_warning_bps", self.single_provider_warning_bps, maximum=10000)
        _positive_int("single_provider_limit_bps", self.single_provider_limit_bps, maximum=10000)
        _positive_int("high_critical_exposure_limit_bps", self.high_critical_exposure_limit_bps, maximum=10000)
        if self.single_provider_warning_bps >= self.single_provider_limit_bps:
            raise GovernanceError("single-provider warning threshold must be lower than breach limit")
        if self.require_exit_plan_for_material is not True:
            raise GovernanceError("v0.5 portfolio policy requires exit plans for material dependencies")
        if self.require_tested_exit_for_critical is not True:
            raise GovernanceError("v0.5 portfolio policy requires tested exit plans for critical dependencies")
        if self.degrade_low_substitutability is not True:
            raise GovernanceError("v0.5 portfolio policy must surface low substitutability as degraded risk")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def default_portfolio_risk_policy(institution_id: str = "default") -> PortfolioRiskPolicy:
    return PortfolioRiskPolicy(
        institution_id=institution_id,
        policy_id="modelriskops-default-portfolio-policy",
        version="1",
        single_provider_warning_bps=2500,
        single_provider_limit_bps=4000,
        high_critical_exposure_limit_bps=6000,
        require_exit_plan_for_material=True,
        require_tested_exit_for_critical=True,
        degrade_low_substitutability=True,
    )


@dataclass(frozen=True, slots=True)
class PortfolioPosition:
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    risk_decision_digest: str
    residual_risk_tier: RiskTier
    exposure_weight_bps: int
    third_party_dependency_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("model_version_digest", self.model_version_digest)
        _digest("risk_decision_digest", self.risk_decision_digest)
        if not isinstance(self.residual_risk_tier, RiskTier):
            raise GovernanceError("portfolio position residual risk tier must be governed")
        _positive_int("exposure_weight_bps", self.exposure_weight_bps, maximum=10000)
        object.__setattr__(
            self,
            "third_party_dependency_digests",
            _canonical_digest_tuple(
                "third_party_dependency_digests",
                self.third_party_dependency_digests,
                allow_empty=True,
            ),
        )

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PortfolioSnapshot:
    institution_id: str
    portfolio_id: str
    snapshot_version: int
    inventory_snapshot_digest: str
    positions: tuple[PortfolioPosition, ...]
    as_of_time: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "portfolio_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("snapshot_version", self.snapshot_version)
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        _timestamp("as_of_time", self.as_of_time)
        if not self.positions or any(not isinstance(item, PortfolioPosition) for item in self.positions):
            raise GovernanceError("portfolio snapshot must contain PortfolioPosition values")
        ordered = tuple(sorted(self.positions, key=lambda item: (item.model_id, item.version_id)))
        if ordered != self.positions:
            raise GovernanceError("portfolio positions must be canonically sorted")
        identities = tuple((item.model_id, item.version_id) for item in self.positions)
        if len(identities) != len(set(identities)):
            raise GovernanceError("portfolio snapshot must not repeat a model/version")
        model_ids = tuple(item.model_id for item in self.positions)
        if len(model_ids) != len(set(model_ids)):
            raise GovernanceError("portfolio snapshot must contain at most one current version per model")
        if any(item.institution_id != self.institution_id for item in self.positions):
            raise GovernanceError("portfolio positions must remain within one institution")
        if sum(item.exposure_weight_bps for item in self.positions) != 10000:
            raise GovernanceError("portfolio exposure weights must sum to exactly 10000 basis points")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ProviderExposure:
    provider_id: str
    provider_profile_digest: str
    exposure_bps: int
    model_count: int
    dependency_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _text("provider_id", self.provider_id))
        _digest("provider_profile_digest", self.provider_profile_digest)
        _positive_int("exposure_bps", self.exposure_bps, maximum=10000)
        _positive_int("model_count", self.model_count)
        _positive_int("dependency_count", self.dependency_count)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PortfolioAssessment:
    institution_id: str
    portfolio_id: str
    snapshot_digest: str
    policy_digest: str
    assessed_at: int
    state: PortfolioAssessmentState
    provider_exposures: tuple[ProviderExposure, ...]
    third_party_exposure_bps: int
    high_critical_exposure_bps: int
    findings: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("institution_id", "portfolio_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("snapshot_digest", self.snapshot_digest)
        _digest("policy_digest", self.policy_digest)
        _timestamp("assessed_at", self.assessed_at)
        if not isinstance(self.state, PortfolioAssessmentState):
            raise GovernanceError("portfolio assessment state must be governed")
        ordered = tuple(sorted(self.provider_exposures, key=lambda item: item.provider_id))
        if ordered != self.provider_exposures:
            raise GovernanceError("provider exposure rows must be canonically sorted")
        providers = tuple(item.provider_id for item in self.provider_exposures)
        if len(providers) != len(set(providers)):
            raise GovernanceError("provider exposure rows must be unique by provider")
        if not 0 <= self.third_party_exposure_bps <= 10000:
            raise GovernanceError("third-party exposure must be between 0 and 10000 basis points")
        if not 0 <= self.high_critical_exposure_bps <= 10000:
            raise GovernanceError("high/critical exposure must be between 0 and 10000 basis points")
        cleaned_findings = _canonical_text_tuple("findings", self.findings, allow_empty=True)
        if cleaned_findings != self.findings:
            raise GovernanceError("portfolio findings must be canonically sorted and unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PortfolioEvidencePackage:
    institution_id: str
    portfolio_id: str
    snapshot_digest: str
    policy_digest: str
    assessment_digest: str
    provider_profile_digests: tuple[str, ...]
    dependency_digests: tuple[str, ...]
    exit_plan_digests: tuple[str, ...]
    state: PortfolioAssessmentState
    generated_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "portfolio_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("snapshot_digest", "policy_digest", "assessment_digest"):
            _digest(name, getattr(self, name))
        for name in ("provider_profile_digests", "dependency_digests", "exit_plan_digests"):
            object.__setattr__(
                self,
                name,
                _canonical_digest_tuple(name, getattr(self, name), allow_empty=True),
            )
        if not isinstance(self.state, PortfolioAssessmentState):
            raise GovernanceError("portfolio evidence package state must be governed")
        _timestamp("generated_at", self.generated_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class PortfolioRiskRegistry:
    """Offline append-only reference registry for portfolio and third-party model-risk evidence."""

    def __init__(self, inventory_registry: InventoryRegistry) -> None:
        if not isinstance(inventory_registry, InventoryRegistry):
            raise GovernanceError("portfolio registry requires InventoryRegistry")
        self._inventory = inventory_registry
        self._provider_profiles: dict[tuple[str, str, int], ThirdPartyProviderProfile] = {}
        self._current_provider_versions: dict[tuple[str, str], int] = {}
        self._provider_by_digest: dict[str, ThirdPartyProviderProfile] = {}
        self._dependencies: dict[tuple[str, str, str, str, int], ThirdPartyModelDependency] = {}
        self._current_dependency_versions: dict[tuple[str, str, str, str], int] = {}
        self._dependency_by_digest: dict[str, ThirdPartyModelDependency] = {}
        self._exit_plans: dict[tuple[str, str, str, str, int], ThirdPartyExitPlan] = {}
        self._current_exit_plan_versions: dict[tuple[str, str, str, str], int] = {}
        self._exit_plan_by_digest: dict[str, ThirdPartyExitPlan] = {}
        self._snapshots: dict[tuple[str, str, int], PortfolioSnapshot] = {}
        self._current_snapshot_versions: dict[tuple[str, str], int] = {}
        self._snapshot_by_digest: dict[str, PortfolioSnapshot] = {}
        self._risk_decisions: dict[str, RiskDecision] = {}

    def register_provider_profile(self, profile: ThirdPartyProviderProfile) -> str:
        key = (profile.institution_id, profile.provider_id, profile.profile_version)
        existing = self._provider_profiles.get(key)
        if existing is not None:
            if existing.evidence_digest != profile.evidence_digest:
                raise GovernanceError("provider profile version already exists with different content")
            return existing.evidence_digest
        identity = (profile.institution_id, profile.provider_id)
        previous_version = self._current_provider_versions.get(identity, 0)
        if profile.profile_version != previous_version + 1:
            raise GovernanceError("provider profile versions must be contiguous")
        if previous_version:
            previous = self._provider_profiles[(profile.institution_id, profile.provider_id, previous_version)]
            if profile.registered_at <= previous.registered_at:
                raise GovernanceError("provider profile versions must advance registration time")
        self._provider_profiles[key] = profile
        self._current_provider_versions[identity] = profile.profile_version
        self._provider_by_digest[profile.evidence_digest] = profile
        return profile.evidence_digest

    def current_provider_profile(self, institution_id: str, provider_id: str) -> ThirdPartyProviderProfile:
        identity = (institution_id, provider_id)
        try:
            version = self._current_provider_versions[identity]
            return self._provider_profiles[(institution_id, provider_id, version)]
        except KeyError as exc:
            raise GovernanceError("unknown third-party provider") from exc

    def register_dependency(self, dependency: ThirdPartyModelDependency) -> str:
        key = (
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
            dependency.dependency_id,
            dependency.dependency_version,
        )
        existing = self._dependencies.get(key)
        if existing is not None:
            if existing.evidence_digest != dependency.evidence_digest:
                raise GovernanceError("dependency version already exists with different content")
            return existing.evidence_digest

        model_version = self._inventory.version(
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
        )
        if model_version.evidence_digest != dependency.model_version_digest:
            raise GovernanceError("third-party dependency model-version digest is stale or substituted")
        provider = self.current_provider_profile(dependency.institution_id, dependency.provider_id)
        if provider.evidence_digest != dependency.provider_profile_digest:
            raise GovernanceError("third-party dependency must bind the current provider profile")
        if dependency.registered_at < provider.registered_at:
            raise GovernanceError("third-party dependency cannot predate its provider profile")

        identity = (
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
            dependency.dependency_id,
        )
        previous_version = self._current_dependency_versions.get(identity, 0)
        if dependency.dependency_version != previous_version + 1:
            raise GovernanceError("third-party dependency versions must be contiguous")
        if previous_version:
            previous = self._dependencies[identity + (previous_version,)]
            if dependency.registered_at <= previous.registered_at:
                raise GovernanceError("third-party dependency versions must advance registration time")
        self._dependencies[key] = dependency
        self._current_dependency_versions[identity] = dependency.dependency_version
        self._dependency_by_digest[dependency.evidence_digest] = dependency
        return dependency.evidence_digest

    def dependency_by_digest(self, digest: str) -> ThirdPartyModelDependency:
        _digest("dependency_digest", digest)
        try:
            return self._dependency_by_digest[digest]
        except KeyError as exc:
            raise GovernanceError("unknown third-party dependency digest") from exc

    def assert_dependency_current(self, dependency: ThirdPartyModelDependency) -> None:
        identity = (
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
            dependency.dependency_id,
        )
        try:
            current_version = self._current_dependency_versions[identity]
        except KeyError as exc:
            raise GovernanceError("third-party dependency is not registered") from exc
        current = self._dependencies[identity + (current_version,)]
        if current.evidence_digest != dependency.evidence_digest:
            raise GovernanceError("third-party dependency is stale")
        provider = self.current_provider_profile(dependency.institution_id, dependency.provider_id)
        if provider.evidence_digest != dependency.provider_profile_digest:
            raise GovernanceError("third-party dependency provider profile is stale")
        model_version = self._inventory.version(
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
        )
        if model_version.evidence_digest != dependency.model_version_digest:
            raise GovernanceError("third-party dependency model version is stale")

    def register_exit_plan(self, plan: ThirdPartyExitPlan) -> str:
        supplied_identity = (plan.institution_id, plan.model_id, plan.version_id, plan.dependency_id)
        key = supplied_identity + (plan.plan_version,)
        existing = self._exit_plans.get(key)
        if existing is not None:
            if existing.evidence_digest != plan.evidence_digest:
                raise GovernanceError("exit-plan version already exists with different content")
            return existing.evidence_digest

        dependency = self.dependency_by_digest(plan.dependency_digest)
        self.assert_dependency_current(dependency)
        expected_identity = (
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
            dependency.dependency_id,
        )
        if supplied_identity != expected_identity:
            raise GovernanceError("exit plan does not belong to the bound dependency")
        if plan.created_at < dependency.registered_at:
            raise GovernanceError("exit plan cannot predate its dependency")

        previous_version = self._current_exit_plan_versions.get(expected_identity, 0)
        if plan.plan_version != previous_version + 1:
            raise GovernanceError("exit-plan versions must be contiguous")
        if previous_version:
            previous = self._exit_plans[expected_identity + (previous_version,)]
            if plan.created_at <= previous.created_at:
                raise GovernanceError("exit-plan versions must advance creation time")
        self._exit_plans[key] = plan
        self._current_exit_plan_versions[expected_identity] = plan.plan_version
        self._exit_plan_by_digest[plan.evidence_digest] = plan
        return plan.evidence_digest

    def current_exit_plan(self, dependency: ThirdPartyModelDependency) -> ThirdPartyExitPlan | None:
        identity = (
            dependency.institution_id,
            dependency.model_id,
            dependency.version_id,
            dependency.dependency_id,
        )
        version = self._current_exit_plan_versions.get(identity)
        if version is None:
            return None
        plan = self._exit_plans[identity + (version,)]
        if plan.dependency_digest != dependency.evidence_digest:
            return None
        return plan

    def register_snapshot(
        self,
        snapshot: PortfolioSnapshot,
        risk_decisions: Iterable[RiskDecision],
    ) -> str:
        key = (snapshot.institution_id, snapshot.portfolio_id, snapshot.snapshot_version)
        existing = self._snapshots.get(key)
        if existing is not None:
            if existing.evidence_digest != snapshot.evidence_digest:
                raise GovernanceError("portfolio snapshot version already exists with different content")
            return existing.evidence_digest

        if snapshot.inventory_snapshot_digest != self._inventory.snapshot_digest():
            raise GovernanceError("portfolio snapshot must bind the current inventory snapshot")
        decisions = {item.evidence_digest: item for item in risk_decisions}
        if len(decisions) == 0:
            raise GovernanceError("portfolio snapshot requires exact risk-decision evidence")

        for position in snapshot.positions:
            model_version = self._inventory.version(
                position.institution_id,
                position.model_id,
                position.version_id,
            )
            if model_version.evidence_digest != position.model_version_digest:
                raise GovernanceError("portfolio position model-version digest is stale or substituted")
            try:
                risk = decisions[position.risk_decision_digest]
            except KeyError as exc:
                raise GovernanceError("portfolio position is missing its exact risk decision") from exc
            if (
                risk.institution_id != position.institution_id
                or risk.model_id != position.model_id
                or risk.version_id != position.version_id
                or risk.model_version_digest != position.model_version_digest
            ):
                raise GovernanceError("portfolio risk decision does not belong to the position model/version")
            if risk.residual_tier is not position.residual_risk_tier:
                raise GovernanceError("portfolio residual risk tier does not reproduce from bound risk decision")
            for dependency_digest in position.third_party_dependency_digests:
                dependency = self.dependency_by_digest(dependency_digest)
                self.assert_dependency_current(dependency)
                if (
                    dependency.institution_id != position.institution_id
                    or dependency.model_id != position.model_id
                    or dependency.version_id != position.version_id
                    or dependency.model_version_digest != position.model_version_digest
                ):
                    raise GovernanceError("portfolio position contains a dependency for another model/version")
                if dependency.registered_at > snapshot.as_of_time:
                    raise GovernanceError("portfolio snapshot cannot predate a bound third-party dependency")

        identity = (snapshot.institution_id, snapshot.portfolio_id)
        previous_version = self._current_snapshot_versions.get(identity, 0)
        if snapshot.snapshot_version != previous_version + 1:
            raise GovernanceError("portfolio snapshot versions must be contiguous")
        if previous_version:
            previous = self._snapshots[identity + (previous_version,)]
            if snapshot.as_of_time <= previous.as_of_time:
                raise GovernanceError("portfolio snapshot versions must advance as-of time")
        self._snapshots[key] = snapshot
        self._current_snapshot_versions[identity] = snapshot.snapshot_version
        self._snapshot_by_digest[snapshot.evidence_digest] = snapshot
        for digest, risk in decisions.items():
            self._risk_decisions.setdefault(digest, risk)
        return snapshot.evidence_digest

    def assert_snapshot_current(self, snapshot: PortfolioSnapshot) -> None:
        identity = (snapshot.institution_id, snapshot.portfolio_id)
        try:
            current_version = self._current_snapshot_versions[identity]
        except KeyError as exc:
            raise GovernanceError("portfolio snapshot is not registered") from exc
        current = self._snapshots[identity + (current_version,)]
        if current.evidence_digest != snapshot.evidence_digest:
            raise GovernanceError("portfolio snapshot is stale")
        if snapshot.inventory_snapshot_digest != self._inventory.snapshot_digest():
            raise GovernanceError("portfolio inventory snapshot is stale")
        for position in snapshot.positions:
            for dependency_digest in position.third_party_dependency_digests:
                dependency = self.dependency_by_digest(dependency_digest)
                self.assert_dependency_current(dependency)

    def assess_portfolio(
        self,
        snapshot: PortfolioSnapshot,
        policy: PortfolioRiskPolicy,
        *,
        assessed_at: int,
    ) -> PortfolioAssessment:
        self.assert_snapshot_current(snapshot)
        _timestamp("assessed_at", assessed_at)
        if assessed_at < snapshot.as_of_time:
            raise GovernanceError("portfolio assessment cannot predate its snapshot")
        if policy.institution_id not in {"default", snapshot.institution_id}:
            raise GovernanceError("portfolio risk policy is not applicable to this institution")

        provider_models: dict[str, set[tuple[str, str]]] = {}
        provider_dependency_counts: dict[str, int] = {}
        provider_profiles: dict[str, ThirdPartyProviderProfile] = {}
        provider_exposure: dict[str, int] = {}
        third_party_exposure_bps = 0
        high_critical_exposure_bps = 0
        incomplete: set[str] = set()
        breached: set[str] = set()
        degraded: set[str] = set()

        for position in snapshot.positions:
            if position.residual_risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}:
                high_critical_exposure_bps += position.exposure_weight_bps
            dependencies = tuple(
                self.dependency_by_digest(digest)
                for digest in position.third_party_dependency_digests
            )
            if dependencies:
                third_party_exposure_bps += position.exposure_weight_bps
            providers_for_position: set[str] = set()
            for dependency in dependencies:
                self.assert_dependency_current(dependency)
                profile = self.current_provider_profile(dependency.institution_id, dependency.provider_id)
                provider_profiles[profile.provider_id] = profile
                provider_models.setdefault(profile.provider_id, set()).add((position.model_id, position.version_id))
                provider_dependency_counts[profile.provider_id] = provider_dependency_counts.get(profile.provider_id, 0) + 1
                providers_for_position.add(profile.provider_id)

                if assessed_at >= profile.due_diligence_expires_at:
                    incomplete.add(f"provider_due_diligence_expired:{profile.provider_id}")
                if assessed_at >= profile.contract_expires_at:
                    incomplete.add(f"provider_contract_expired:{profile.provider_id}")

                plan = self.current_exit_plan(dependency)
                if dependency.materiality in {DependencyMateriality.MATERIAL, DependencyMateriality.CRITICAL}:
                    if plan is None:
                        incomplete.add(f"missing_current_exit_plan:{dependency.dependency_id}")
                    elif dependency.materiality is DependencyMateriality.CRITICAL and plan.tested_at is None:
                        incomplete.add(f"untested_critical_exit_plan:{dependency.dependency_id}")
                    if dependency.substitutability in {Substitutability.LOW, Substitutability.NONE}:
                        degraded.add(f"low_substitutability:{dependency.dependency_id}")

            for provider_id in providers_for_position:
                provider_exposure[provider_id] = provider_exposure.get(provider_id, 0) + position.exposure_weight_bps

        if high_critical_exposure_bps > policy.high_critical_exposure_limit_bps:
            breached.add(f"high_critical_exposure_breach:{high_critical_exposure_bps}")

        exposure_rows: list[ProviderExposure] = []
        for provider_id in sorted(provider_exposure):
            exposure_bps = provider_exposure[provider_id]
            if exposure_bps > policy.single_provider_limit_bps:
                breached.add(f"provider_concentration_breach:{provider_id}:{exposure_bps}")
            elif exposure_bps >= policy.single_provider_warning_bps:
                degraded.add(f"provider_concentration_warning:{provider_id}:{exposure_bps}")
            profile = provider_profiles[provider_id]
            exposure_rows.append(
                ProviderExposure(
                    provider_id=provider_id,
                    provider_profile_digest=profile.evidence_digest,
                    exposure_bps=exposure_bps,
                    model_count=len(provider_models[provider_id]),
                    dependency_count=provider_dependency_counts[provider_id],
                )
            )

        if incomplete:
            state = PortfolioAssessmentState.INCOMPLETE
        elif breached:
            state = PortfolioAssessmentState.BREACHED
        elif degraded:
            state = PortfolioAssessmentState.DEGRADED
        else:
            state = PortfolioAssessmentState.HEALTHY
        findings = tuple(sorted(incomplete | breached | degraded))
        return PortfolioAssessment(
            institution_id=snapshot.institution_id,
            portfolio_id=snapshot.portfolio_id,
            snapshot_digest=snapshot.evidence_digest,
            policy_digest=policy.evidence_digest,
            assessed_at=assessed_at,
            state=state,
            provider_exposures=tuple(exposure_rows),
            third_party_exposure_bps=third_party_exposure_bps,
            high_critical_exposure_bps=high_critical_exposure_bps,
            findings=findings,
        )

    def build_evidence_package(
        self,
        snapshot: PortfolioSnapshot,
        policy: PortfolioRiskPolicy,
        assessment: PortfolioAssessment,
        *,
        generated_at: int,
    ) -> PortfolioEvidencePackage:
        self.assert_snapshot_current(snapshot)
        _timestamp("generated_at", generated_at)
        if generated_at < assessment.assessed_at:
            raise GovernanceError("portfolio evidence package cannot predate its assessment")
        reproduced = self.assess_portfolio(snapshot, policy, assessed_at=assessment.assessed_at)
        if reproduced != assessment:
            raise GovernanceError("portfolio assessment does not reproduce from current evidence")

        provider_digests: set[str] = set()
        dependency_digests: set[str] = set()
        exit_plan_digests: set[str] = set()
        for position in snapshot.positions:
            for dependency_digest in position.third_party_dependency_digests:
                dependency = self.dependency_by_digest(dependency_digest)
                self.assert_dependency_current(dependency)
                dependency_digests.add(dependency.evidence_digest)
                provider = self.current_provider_profile(dependency.institution_id, dependency.provider_id)
                provider_digests.add(provider.evidence_digest)
                plan = self.current_exit_plan(dependency)
                if plan is not None:
                    exit_plan_digests.add(plan.evidence_digest)

        return PortfolioEvidencePackage(
            institution_id=snapshot.institution_id,
            portfolio_id=snapshot.portfolio_id,
            snapshot_digest=snapshot.evidence_digest,
            policy_digest=policy.evidence_digest,
            assessment_digest=assessment.evidence_digest,
            provider_profile_digests=tuple(sorted(provider_digests)),
            dependency_digests=tuple(sorted(dependency_digests)),
            exit_plan_digests=tuple(sorted(exit_plan_digests)),
            state=assessment.state,
            generated_at=generated_at,
        )

    def verify_evidence_package(
        self,
        package: PortfolioEvidencePackage,
        snapshot: PortfolioSnapshot,
        policy: PortfolioRiskPolicy,
        assessment: PortfolioAssessment,
    ) -> None:
        reproduced = self.build_evidence_package(
            snapshot,
            policy,
            assessment,
            generated_at=package.generated_at,
        )
        if reproduced != package:
            raise GovernanceError("portfolio evidence package does not reproduce from current evidence")
