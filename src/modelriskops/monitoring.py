from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Iterable

from .canonical import sha256_digest
from .governance import RevalidationRequirement, RevalidationTrigger
from .models import GovernanceError, ModelVersion
from .risk import RiskDecision


class MonitoringLevel(str, Enum):
    STANDARD = "standard"
    ENHANCED = "enhanced"


class MetricKind(str, Enum):
    PERFORMANCE = "performance"
    DATA_DRIFT = "data_drift"
    PREDICTION_DRIFT = "prediction_drift"
    CALIBRATION = "calibration"
    FAIRNESS = "fairness"
    STABILITY = "stability"
    OPERATIONAL = "operational"


class ThresholdDirection(str, Enum):
    ABOVE_IS_WORSE = "above_is_worse"
    BELOW_IS_WORSE = "below_is_worse"


class MetricStatus(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    BREACH = "breach"
    MISSING = "missing"
    STALE = "stale"
    INSUFFICIENT_SAMPLES = "insufficient_samples"


class MonitoringState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BREACHED = "breached"
    INCOMPLETE = "incomplete"


_DRIFT_KINDS = frozenset({MetricKind.DATA_DRIFT, MetricKind.PREDICTION_DRIFT})
_INCOMPLETE_STATUSES = frozenset(
    {MetricStatus.MISSING, MetricStatus.STALE, MetricStatus.INSUFFICIENT_SAMPLES}
)


def _required_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _require_digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _finite(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GovernanceError(f"{name} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise GovernanceError(f"{name} must be a finite number")
    return result


def _integer(name: str, value: int, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        comparator = "positive" if minimum == 1 else "non-negative"
        raise GovernanceError(f"{name} must be a {comparator} integer")
    return value


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    metric_id: str
    kind: MetricKind
    direction: ThresholdDirection
    warning_threshold: float
    breach_threshold: float
    min_samples: int
    reference_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", _required_text("metric_id", self.metric_id))
        warning = _finite("warning_threshold", self.warning_threshold)
        breach = _finite("breach_threshold", self.breach_threshold)
        object.__setattr__(self, "warning_threshold", warning)
        object.__setattr__(self, "breach_threshold", breach)
        if self.direction is ThresholdDirection.ABOVE_IS_WORSE and not warning < breach:
            raise GovernanceError("above-is-worse thresholds require warning < breach")
        if self.direction is ThresholdDirection.BELOW_IS_WORSE and not warning > breach:
            raise GovernanceError("below-is-worse thresholds require warning > breach")
        _integer("min_samples", self.min_samples, minimum=1)
        if self.reference_digest is not None:
            _require_digest("reference_digest", self.reference_digest)
        if self.kind in _DRIFT_KINDS and self.reference_digest is None:
            raise GovernanceError("drift metrics require an exact reference_digest")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class MonitoringPlan:
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    risk_decision_digest: str
    monitoring_level: MonitoringLevel
    cadence_seconds: int
    max_staleness_seconds: int
    metrics: tuple[MetricDefinition, ...]

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        _require_digest("model_version_digest", self.model_version_digest)
        _require_digest("risk_decision_digest", self.risk_decision_digest)
        _integer("cadence_seconds", self.cadence_seconds, minimum=1)
        _integer("max_staleness_seconds", self.max_staleness_seconds, minimum=1)
        if self.max_staleness_seconds < self.cadence_seconds:
            raise GovernanceError("max_staleness_seconds must be at least cadence_seconds")
        if not self.metrics:
            raise GovernanceError("monitoring plan must define at least one metric")
        metric_ids = tuple(metric.metric_id for metric in self.metrics)
        if len(metric_ids) != len(set(metric_ids)):
            raise GovernanceError("monitoring metric_id values must be unique")
        if self.monitoring_level is MonitoringLevel.ENHANCED:
            kinds = {metric.kind for metric in self.metrics}
            if len(self.metrics) < 3 or not kinds.intersection(_DRIFT_KINDS):
                raise GovernanceError(
                    "enhanced monitoring requires at least three metrics including a drift metric"
                )

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class MonitoringObservation:
    monitoring_plan_digest: str
    metric_id: str
    window_start: int
    window_end: int
    observed_at: int
    value: float
    sample_size: int
    source_evidence_digest: str

    def __post_init__(self) -> None:
        _require_digest("monitoring_plan_digest", self.monitoring_plan_digest)
        object.__setattr__(self, "metric_id", _required_text("metric_id", self.metric_id))
        _integer("window_start", self.window_start, minimum=0)
        _integer("window_end", self.window_end, minimum=1)
        _integer("observed_at", self.observed_at, minimum=1)
        if self.window_end <= self.window_start:
            raise GovernanceError("monitoring window end must be after its start")
        if self.observed_at < self.window_end:
            raise GovernanceError("observed_at cannot precede the end of its monitoring window")
        object.__setattr__(self, "value", _finite("value", self.value))
        _integer("sample_size", self.sample_size, minimum=0)
        _require_digest("source_evidence_digest", self.source_evidence_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class MetricAssessment:
    metric_id: str
    status: MetricStatus
    observation_digest: str | None
    measured_value: float | None
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", _required_text("metric_id", self.metric_id))
        object.__setattr__(self, "reason", _required_text("reason", self.reason))
        if self.observation_digest is not None:
            _require_digest("observation_digest", self.observation_digest)
        if self.measured_value is not None:
            object.__setattr__(self, "measured_value", _finite("measured_value", self.measured_value))


@dataclass(frozen=True, slots=True)
class MonitoringAssessment:
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    risk_decision_digest: str
    monitoring_plan_digest: str
    as_of: int
    state: MonitoringState
    metric_assessments: tuple[MetricAssessment, ...]
    observation_digests: tuple[str, ...]
    revalidation_required: bool

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            object.__setattr__(self, name, _required_text(name, getattr(self, name)))
        for name in (
            "model_version_digest",
            "risk_decision_digest",
            "monitoring_plan_digest",
        ):
            _require_digest(name, getattr(self, name))
        _integer("as_of", self.as_of, minimum=0)
        metric_ids = tuple(item.metric_id for item in self.metric_assessments)
        if len(metric_ids) != len(set(metric_ids)):
            raise GovernanceError("metric assessments must be unique by metric_id")
        for digest in self.observation_digests:
            _require_digest("observation_digest", digest)
        if len(self.observation_digests) != len(set(self.observation_digests)):
            raise GovernanceError("observation_digests must be unique")
        if not isinstance(self.revalidation_required, bool):
            raise GovernanceError("revalidation_required must be boolean")
        expected_revalidation = self.state in {MonitoringState.BREACHED, MonitoringState.INCOMPLETE}
        if self.revalidation_required is not expected_revalidation:
            raise GovernanceError("revalidation_required is inconsistent with monitoring state")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _assert_current(plan: MonitoringPlan, version: ModelVersion, risk: RiskDecision) -> None:
    if (
        plan.institution_id != version.institution_id
        or plan.model_id != version.model_id
        or plan.version_id != version.version_id
    ):
        raise GovernanceError("monitoring plan identity does not match model version")
    if plan.model_version_digest != version.evidence_digest:
        raise GovernanceError("monitoring plan is stale for model version")
    if risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    if plan.risk_decision_digest != risk.evidence_digest:
        raise GovernanceError("monitoring plan is stale for risk decision")


def build_monitoring_plan(
    version: ModelVersion,
    risk: RiskDecision,
    metrics: Iterable[MetricDefinition],
    *,
    cadence_seconds: int,
    max_staleness_seconds: int,
) -> MonitoringPlan:
    if risk.institution_id != version.institution_id or risk.model_id != version.model_id:
        raise GovernanceError("risk decision identity does not match model version")
    if risk.version_id != version.version_id or risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    level = (
        MonitoringLevel.ENHANCED
        if "enhanced_monitoring" in risk.requirements
        else MonitoringLevel.STANDARD
    )
    return MonitoringPlan(
        institution_id=version.institution_id,
        model_id=version.model_id,
        version_id=version.version_id,
        model_version_digest=version.evidence_digest,
        risk_decision_digest=risk.evidence_digest,
        monitoring_level=level,
        cadence_seconds=cadence_seconds,
        max_staleness_seconds=max_staleness_seconds,
        metrics=tuple(sorted(metrics, key=lambda item: item.metric_id)),
    )


def _evaluate_metric(
    definition: MetricDefinition,
    observation: MonitoringObservation | None,
    *,
    as_of: int,
    max_staleness_seconds: int,
) -> MetricAssessment:
    if observation is None:
        return MetricAssessment(
            metric_id=definition.metric_id,
            status=MetricStatus.MISSING,
            observation_digest=None,
            measured_value=None,
            reason="required monitoring observation is missing",
        )
    if as_of - observation.observed_at > max_staleness_seconds:
        return MetricAssessment(
            metric_id=definition.metric_id,
            status=MetricStatus.STALE,
            observation_digest=observation.evidence_digest,
            measured_value=observation.value,
            reason="latest monitoring observation exceeds the freshness limit",
        )
    if observation.sample_size < definition.min_samples:
        return MetricAssessment(
            metric_id=definition.metric_id,
            status=MetricStatus.INSUFFICIENT_SAMPLES,
            observation_digest=observation.evidence_digest,
            measured_value=observation.value,
            reason="latest monitoring observation does not meet min_samples",
        )

    if definition.direction is ThresholdDirection.ABOVE_IS_WORSE:
        if observation.value >= definition.breach_threshold:
            status = MetricStatus.BREACH
            reason = "metric reached or exceeded breach threshold"
        elif observation.value >= definition.warning_threshold:
            status = MetricStatus.WARNING
            reason = "metric reached or exceeded warning threshold"
        else:
            status = MetricStatus.PASS
            reason = "metric remains below warning threshold"
    else:
        if observation.value <= definition.breach_threshold:
            status = MetricStatus.BREACH
            reason = "metric reached or fell below breach threshold"
        elif observation.value <= definition.warning_threshold:
            status = MetricStatus.WARNING
            reason = "metric reached or fell below warning threshold"
        else:
            status = MetricStatus.PASS
            reason = "metric remains above warning threshold"

    return MetricAssessment(
        metric_id=definition.metric_id,
        status=status,
        observation_digest=observation.evidence_digest,
        measured_value=observation.value,
        reason=reason,
    )


def assess_monitoring(
    plan: MonitoringPlan,
    version: ModelVersion,
    risk: RiskDecision,
    observations: Iterable[MonitoringObservation],
    *,
    as_of: int,
) -> MonitoringAssessment:
    _assert_current(plan, version, risk)
    _integer("as_of", as_of, minimum=0)

    definitions = {metric.metric_id: metric for metric in plan.metrics}
    grouped: dict[str, list[MonitoringObservation]] = {metric_id: [] for metric_id in definitions}
    for observation in observations:
        if observation.monitoring_plan_digest != plan.evidence_digest:
            raise GovernanceError("monitoring observation is bound to a different plan")
        if observation.metric_id not in definitions:
            raise GovernanceError("monitoring observation references an unknown metric_id")
        if observation.observed_at > as_of:
            raise GovernanceError("monitoring observation cannot be in the future relative to as_of")
        grouped[observation.metric_id].append(observation)

    latest: dict[str, MonitoringObservation] = {}
    for metric_id, items in grouped.items():
        if not items:
            continue
        latest_at = max(item.observed_at for item in items)
        candidates = [item for item in items if item.observed_at == latest_at]
        digests = {item.evidence_digest for item in candidates}
        if len(digests) > 1:
            raise GovernanceError("conflicting latest monitoring observations fail closed")
        latest[metric_id] = candidates[0]

    metric_assessments = tuple(
        _evaluate_metric(
            definition,
            latest.get(definition.metric_id),
            as_of=as_of,
            max_staleness_seconds=plan.max_staleness_seconds,
        )
        for definition in plan.metrics
    )
    statuses = {item.status for item in metric_assessments}
    if statuses.intersection(_INCOMPLETE_STATUSES):
        state = MonitoringState.INCOMPLETE
    elif MetricStatus.BREACH in statuses:
        state = MonitoringState.BREACHED
    elif MetricStatus.WARNING in statuses:
        state = MonitoringState.DEGRADED
    else:
        state = MonitoringState.HEALTHY

    selected_digests = tuple(
        latest[metric.metric_id].evidence_digest
        for metric in plan.metrics
        if metric.metric_id in latest
    )
    return MonitoringAssessment(
        institution_id=version.institution_id,
        model_id=version.model_id,
        version_id=version.version_id,
        model_version_digest=version.evidence_digest,
        risk_decision_digest=risk.evidence_digest,
        monitoring_plan_digest=plan.evidence_digest,
        as_of=as_of,
        state=state,
        metric_assessments=metric_assessments,
        observation_digests=selected_digests,
        revalidation_required=state in {MonitoringState.BREACHED, MonitoringState.INCOMPLETE},
    )


def derive_monitoring_revalidation(
    assessment: MonitoringAssessment,
    version: ModelVersion,
    risk: RiskDecision,
) -> RevalidationRequirement:
    if not assessment.revalidation_required:
        raise GovernanceError("monitoring assessment does not require revalidation")
    if (
        assessment.institution_id != version.institution_id
        or assessment.model_id != version.model_id
        or assessment.version_id != version.version_id
        or assessment.model_version_digest != version.evidence_digest
    ):
        raise GovernanceError("monitoring assessment is stale for model version")
    if risk.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    if assessment.risk_decision_digest != risk.evidence_digest:
        raise GovernanceError("monitoring assessment is stale for risk decision")

    actionable = tuple(
        f"{item.metric_id}:{item.status.value}"
        for item in assessment.metric_assessments
        if item.status in _INCOMPLETE_STATUSES or item.status is MetricStatus.BREACH
    )
    return RevalidationRequirement(
        institution_id=version.institution_id,
        model_id=version.model_id,
        before_state_digest=sha256_digest(
            {
                "model_version_digest": version.evidence_digest,
                "risk_decision_digest": risk.evidence_digest,
                "monitoring_plan_digest": assessment.monitoring_plan_digest,
            }
        ),
        after_state_digest=sha256_digest(
            {"monitoring_assessment_digest": assessment.evidence_digest}
        ),
        triggers=(RevalidationTrigger.MONITORING_DETERIORATION,),
        rationale="monitoring evidence requires revalidation: " + ", ".join(actionable),
    )
