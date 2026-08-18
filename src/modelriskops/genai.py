from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
from typing import Iterable

from .canonical import sha256_digest
from .governance import RevalidationRequirement, RevalidationTrigger
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskPolicyProfile


class GenAIMetricKind(str, Enum):
    FACTUALITY = "factuality"
    GROUNDEDNESS = "groundedness"
    HARMFUL_CONTENT = "harmful_content"
    PROMPT_INJECTION_RESISTANCE = "prompt_injection_resistance"
    PRIVACY_LEAKAGE = "privacy_leakage"
    FAIRNESS_BIAS = "fairness_bias"
    TOOL_CONTROL = "tool_control"
    OPERATIONAL_ROBUSTNESS = "operational_robustness"


class MetricDirection(str, Enum):
    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


class GenAIMetricStatus(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    BREACH = "breach"
    INCOMPLETE = "incomplete"


class GenAIEvaluationState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    BREACHED = "breached"
    INCOMPLETE = "incomplete"


class HumanOversightDecisionKind(str, Enum):
    ACCEPT = "accept"
    ESCALATE = "escalate"
    REJECT = "reject"


class GenAIRevalidationTrigger(str, Enum):
    FOUNDATION_MODEL = "foundation_model"
    PROMPT_POLICY = "prompt_policy"
    RETRIEVAL_CORPUS = "retrieval_corpus"
    EMBEDDING_MODEL = "embedding_model"
    TOOL_SCOPE = "tool_scope"
    SAFETY_POLICY = "safety_policy"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _finite(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise GovernanceError(f"{name} must be a finite number")
    return float(value)


def _unique_text(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_text(name, item) for item in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must contain at least one value")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must contain unique values")
    return cleaned


def _same_scope(*artifacts) -> tuple[str, str, str]:
    scopes = {(a.institution_id, a.model_id, a.version_id) for a in artifacts}
    if len(scopes) != 1:
        raise GovernanceError("GenAI artifacts must share exact institution/model/version scope")
    return next(iter(scopes))


@dataclass(frozen=True, slots=True)
class FoundationModelDependency:
    institution_id: str
    model_id: str
    version_id: str
    provider: str
    provider_model_id: str
    provider_model_version: str
    deployment_id: str
    owner_id: str
    artifact_digest: str
    config_digest: str
    terms_evidence_digest: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in (
            "institution_id", "model_id", "version_id", "provider", "provider_model_id",
            "provider_model_version", "deployment_id", "owner_id",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("artifact_digest", "config_digest", "terms_evidence_digest"):
            _digest(name, getattr(self, name))
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PromptPolicyArtifact:
    institution_id: str
    model_id: str
    version_id: str
    prompt_policy_id: str
    policy_version: str
    owner_id: str
    intended_purpose: str
    prompt_digest: str
    safety_policy_digest: str
    prohibited_behaviors: tuple[str, ...]
    registered_at: int

    def __post_init__(self) -> None:
        for name in (
            "institution_id", "model_id", "version_id", "prompt_policy_id", "policy_version",
            "owner_id", "intended_purpose",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("prompt_digest", self.prompt_digest)
        _digest("safety_policy_digest", self.safety_policy_digest)
        object.__setattr__(self, "prohibited_behaviors", _unique_text("prohibited_behaviors", self.prohibited_behaviors))
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RAGConfiguration:
    institution_id: str
    model_id: str
    version_id: str
    rag_id: str
    config_version: str
    owner_id: str
    corpus_id: str
    corpus_version: str
    corpus_digest: str
    index_digest: str
    embedding_model_id: str
    embedding_model_version: str
    embedding_model_digest: str
    chunking_policy_digest: str
    retrieval_policy_digest: str
    source_set_digest: str
    require_citations: bool
    registered_at: int

    def __post_init__(self) -> None:
        for name in (
            "institution_id", "model_id", "version_id", "rag_id", "config_version", "owner_id",
            "corpus_id", "corpus_version", "embedding_model_id", "embedding_model_version",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "corpus_digest", "index_digest", "embedding_model_digest", "chunking_policy_digest",
            "retrieval_policy_digest", "source_set_digest",
        ):
            _digest(name, getattr(self, name))
        if type(self.require_citations) is not bool:
            raise GovernanceError("require_citations must be a boolean")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class GenAIUseCaseProfile:
    institution_id: str
    model_id: str
    version_id: str
    use_case_id: str
    owner_id: str
    intended_users: tuple[str, ...]
    prohibited_uses: tuple[str, ...]
    output_handling: str
    human_review_required: bool
    high_impact_use: bool
    permitted_tool_actions: tuple[str, ...] = field(default_factory=tuple)
    registered_at: int = 0

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "use_case_id", "owner_id", "output_handling"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "intended_users", _unique_text("intended_users", self.intended_users))
        object.__setattr__(self, "prohibited_uses", _unique_text("prohibited_uses", self.prohibited_uses, allow_empty=True))
        object.__setattr__(self, "permitted_tool_actions", _unique_text("permitted_tool_actions", self.permitted_tool_actions, allow_empty=True))
        if type(self.human_review_required) is not bool or type(self.high_impact_use) is not bool:
            raise GovernanceError("human_review_required and high_impact_use must be booleans")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class GenAIOverlaySnapshot:
    institution_id: str
    model_id: str
    version_id: str
    foundation_model_digest: str
    prompt_policy_digest: str
    rag_configuration_digest: str | None
    use_case_digest: str

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("foundation_model_digest", "prompt_policy_digest", "use_case_digest"):
            _digest(name, getattr(self, name))
        if self.rag_configuration_digest is not None:
            _digest("rag_configuration_digest", self.rag_configuration_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def build_genai_overlay_snapshot(
    foundation: FoundationModelDependency,
    prompt_policy: PromptPolicyArtifact,
    use_case: GenAIUseCaseProfile,
    rag: RAGConfiguration | None = None,
) -> GenAIOverlaySnapshot:
    artifacts = [foundation, prompt_policy, use_case]
    if rag is not None:
        artifacts.append(rag)
    institution_id, model_id, version_id = _same_scope(*artifacts)
    return GenAIOverlaySnapshot(
        institution_id=institution_id,
        model_id=model_id,
        version_id=version_id,
        foundation_model_digest=foundation.evidence_digest,
        prompt_policy_digest=prompt_policy.evidence_digest,
        rag_configuration_digest=(rag.evidence_digest if rag is not None else None),
        use_case_digest=use_case.evidence_digest,
    )


@dataclass(frozen=True, slots=True)
class GenAIMetricDefinition:
    metric_id: str
    kind: GenAIMetricKind
    direction: MetricDirection
    pass_threshold: float
    warning_threshold: float | None
    minimum_sample_size: int
    max_age_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", _text("metric_id", self.metric_id))
        if not isinstance(self.kind, GenAIMetricKind) or not isinstance(self.direction, MetricDirection):
            raise GovernanceError("metric kind/direction must use governed enums")
        object.__setattr__(self, "pass_threshold", _finite("pass_threshold", self.pass_threshold))
        if self.warning_threshold is not None:
            object.__setattr__(self, "warning_threshold", _finite("warning_threshold", self.warning_threshold))
            if self.direction is MetricDirection.HIGHER_IS_BETTER and self.warning_threshold > self.pass_threshold:
                raise GovernanceError("higher-is-better warning threshold cannot exceed pass threshold")
            if self.direction is MetricDirection.LOWER_IS_BETTER and self.warning_threshold < self.pass_threshold:
                raise GovernanceError("lower-is-better warning threshold cannot be below pass threshold")
        _positive_int("minimum_sample_size", self.minimum_sample_size)
        _positive_int("max_age_seconds", self.max_age_seconds)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class GenAIEvaluationPlan:
    institution_id: str
    model_id: str
    version_id: str
    model_version_digest: str
    overlay_snapshot_digest: str
    evaluator_owner_id: str
    metrics: tuple[GenAIMetricDefinition, ...]
    planned_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "evaluator_owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("model_version_digest", self.model_version_digest)
        _digest("overlay_snapshot_digest", self.overlay_snapshot_digest)
        if not self.metrics:
            raise GovernanceError("GenAI evaluation plan requires metrics")
        ids = [metric.metric_id for metric in self.metrics]
        kinds = [metric.kind for metric in self.metrics]
        if len(ids) != len(set(ids)) or len(kinds) != len(set(kinds)):
            raise GovernanceError("GenAI evaluation plan metric ids and kinds must be unique")
        _timestamp("planned_at", self.planned_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def build_genai_evaluation_plan(
    record: ModelRecord,
    version: ModelVersion,
    overlay: GenAIOverlaySnapshot,
    *,
    evaluator_owner_id: str,
    metrics: Iterable[GenAIMetricDefinition],
    planned_at: int,
) -> GenAIEvaluationPlan:
    if (record.institution_id, record.model_id) != (version.institution_id, version.model_id):
        raise GovernanceError("model record/version scope mismatch")
    if (overlay.institution_id, overlay.model_id, overlay.version_id) != (
        version.institution_id, version.model_id, version.version_id
    ):
        raise GovernanceError("GenAI overlay is stale for exact model version")
    return GenAIEvaluationPlan(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        model_version_digest=version.evidence_digest,
        overlay_snapshot_digest=overlay.evidence_digest,
        evaluator_owner_id=evaluator_owner_id,
        metrics=tuple(metrics),
        planned_at=planned_at,
    )


@dataclass(frozen=True, slots=True)
class GenAIEvaluationObservation:
    plan_digest: str
    metric_id: str
    value: float
    observed_at: int
    sample_size: int
    source_evidence_digest: str
    evaluator_id: str

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        object.__setattr__(self, "metric_id", _text("metric_id", self.metric_id))
        object.__setattr__(self, "value", _finite("value", self.value))
        _timestamp("observed_at", self.observed_at)
        _positive_int("sample_size", self.sample_size)
        _digest("source_evidence_digest", self.source_evidence_digest)
        object.__setattr__(self, "evaluator_id", _text("evaluator_id", self.evaluator_id))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class GenAIMetricAssessment:
    metric_id: str
    status: GenAIMetricStatus
    observation_digest: str | None
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "metric_id", _text("metric_id", self.metric_id))
        if not isinstance(self.status, GenAIMetricStatus):
            raise GovernanceError("metric status must be a GenAIMetricStatus")
        if self.observation_digest is not None:
            _digest("observation_digest", self.observation_digest)
        object.__setattr__(self, "reason", _text("reason", self.reason))


@dataclass(frozen=True, slots=True)
class GenAIEvaluationAssessment:
    institution_id: str
    model_id: str
    version_id: str
    plan_digest: str
    overlay_snapshot_digest: str
    evaluated_at: int
    state: GenAIEvaluationState
    metric_assessments: tuple[GenAIMetricAssessment, ...]
    gaps: tuple[str, ...]
    model_safety_determined: bool = False
    regulatory_compliance_determined: bool = False

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("plan_digest", self.plan_digest)
        _digest("overlay_snapshot_digest", self.overlay_snapshot_digest)
        _timestamp("evaluated_at", self.evaluated_at)
        if not isinstance(self.state, GenAIEvaluationState):
            raise GovernanceError("evaluation state must be a GenAIEvaluationState")
        if len(self.gaps) != len(set(self.gaps)) or tuple(sorted(self.gaps)) != self.gaps:
            raise GovernanceError("evaluation gaps must be sorted and unique")
        if self.model_safety_determined or self.regulatory_compliance_determined:
            raise GovernanceError("GenAI evaluation does not determine model safety or regulatory compliance")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _metric_status(metric: GenAIMetricDefinition, value: float) -> GenAIMetricStatus:
    if metric.direction is MetricDirection.HIGHER_IS_BETTER:
        if value >= metric.pass_threshold:
            return GenAIMetricStatus.PASS
        if metric.warning_threshold is not None and value >= metric.warning_threshold:
            return GenAIMetricStatus.WARNING
        return GenAIMetricStatus.BREACH
    if value <= metric.pass_threshold:
        return GenAIMetricStatus.PASS
    if metric.warning_threshold is not None and value <= metric.warning_threshold:
        return GenAIMetricStatus.WARNING
    return GenAIMetricStatus.BREACH


def assess_genai_evaluation(
    plan: GenAIEvaluationPlan,
    overlay: GenAIOverlaySnapshot,
    observations: Iterable[GenAIEvaluationObservation],
    *,
    evaluated_at: int,
) -> GenAIEvaluationAssessment:
    _timestamp("evaluated_at", evaluated_at)
    if plan.overlay_snapshot_digest != overlay.evidence_digest:
        raise GovernanceError("GenAI evaluation plan is stale for current overlay snapshot")
    supplied = tuple(observations)
    by_metric: dict[str, list[GenAIEvaluationObservation]] = {}
    for observation in supplied:
        if observation.plan_digest != plan.evidence_digest:
            raise GovernanceError("GenAI observation is bound to a different evaluation plan")
        if observation.metric_id not in {metric.metric_id for metric in plan.metrics}:
            raise GovernanceError("GenAI observation references unknown metric")
        if observation.observed_at > evaluated_at:
            raise GovernanceError("GenAI observation cannot be from the future")
        by_metric.setdefault(observation.metric_id, []).append(observation)

    assessments: list[GenAIMetricAssessment] = []
    gaps: set[str] = set()
    for metric in plan.metrics:
        candidates = by_metric.get(metric.metric_id, [])
        if not candidates:
            gaps.add(f"missing_observation:{metric.metric_id}")
            assessments.append(GenAIMetricAssessment(metric.metric_id, GenAIMetricStatus.INCOMPLETE, None, "missing observation"))
            continue
        latest_time = max(item.observed_at for item in candidates)
        latest = [item for item in candidates if item.observed_at == latest_time]
        if len({item.evidence_digest for item in latest}) > 1:
            gaps.add(f"conflicting_latest:{metric.metric_id}")
            assessments.append(GenAIMetricAssessment(metric.metric_id, GenAIMetricStatus.INCOMPLETE, None, "conflicting latest observations"))
            continue
        observation = latest[0]
        if evaluated_at - observation.observed_at > metric.max_age_seconds:
            gaps.add(f"stale_observation:{metric.metric_id}")
            assessments.append(GenAIMetricAssessment(metric.metric_id, GenAIMetricStatus.INCOMPLETE, observation.evidence_digest, "stale observation"))
            continue
        if observation.sample_size < metric.minimum_sample_size:
            gaps.add(f"insufficient_sample:{metric.metric_id}")
            assessments.append(GenAIMetricAssessment(metric.metric_id, GenAIMetricStatus.INCOMPLETE, observation.evidence_digest, "insufficient sample size"))
            continue
        status = _metric_status(metric, observation.value)
        assessments.append(GenAIMetricAssessment(metric.metric_id, status, observation.evidence_digest, "threshold evaluation"))

    statuses = {item.status for item in assessments}
    if GenAIMetricStatus.INCOMPLETE in statuses:
        state = GenAIEvaluationState.INCOMPLETE
    elif GenAIMetricStatus.BREACH in statuses:
        state = GenAIEvaluationState.BREACHED
    elif GenAIMetricStatus.WARNING in statuses:
        state = GenAIEvaluationState.DEGRADED
    else:
        state = GenAIEvaluationState.HEALTHY
    return GenAIEvaluationAssessment(
        institution_id=plan.institution_id,
        model_id=plan.model_id,
        version_id=plan.version_id,
        plan_digest=plan.evidence_digest,
        overlay_snapshot_digest=overlay.evidence_digest,
        evaluated_at=evaluated_at,
        state=state,
        metric_assessments=tuple(assessments),
        gaps=tuple(sorted(gaps)),
    )


@dataclass(frozen=True, slots=True)
class HumanOversightRequirement:
    institution_id: str
    model_id: str
    version_id: str
    use_case_digest: str
    evaluation_plan_digest: str
    required: bool
    required_roles: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("use_case_digest", self.use_case_digest)
        _digest("evaluation_plan_digest", self.evaluation_plan_digest)
        if type(self.required) is not bool:
            raise GovernanceError("required must be a boolean")
        roles = _unique_text("required_roles", self.required_roles, allow_empty=not self.required)
        if self.required and not roles:
            raise GovernanceError("required human oversight must define roles")
        if not self.required and roles:
            raise GovernanceError("non-required human oversight cannot define mandatory roles")
        object.__setattr__(self, "required_roles", roles)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def create_human_oversight_requirement(
    use_case: GenAIUseCaseProfile,
    plan: GenAIEvaluationPlan,
    *,
    required: bool,
    required_roles: Iterable[str] = (),
    rationale: str,
) -> HumanOversightRequirement:
    if (use_case.institution_id, use_case.model_id, use_case.version_id) != (plan.institution_id, plan.model_id, plan.version_id):
        raise GovernanceError("human oversight use case/plan scope mismatch")
    if required is False and (use_case.human_review_required or use_case.high_impact_use):
        raise GovernanceError("explicit use-case review requirement cannot be weakened by oversight artifact")
    return HumanOversightRequirement(
        institution_id=use_case.institution_id,
        model_id=use_case.model_id,
        version_id=use_case.version_id,
        use_case_digest=use_case.evidence_digest,
        evaluation_plan_digest=plan.evidence_digest,
        required=required,
        required_roles=tuple(required_roles),
        rationale=rationale,
    )


@dataclass(frozen=True, slots=True)
class HumanOversightDecision:
    requirement_digest: str
    reviewer_id: str
    reviewer_role: str
    decision: HumanOversightDecisionKind
    rationale: str
    evidence_digest: str
    decided_at: int
    effective_oversight_determined: bool = False

    def __post_init__(self) -> None:
        _digest("requirement_digest", self.requirement_digest)
        for name in ("reviewer_id", "reviewer_role", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.decision, HumanOversightDecisionKind):
            raise GovernanceError("decision must be a HumanOversightDecisionKind")
        _digest("evidence_digest", self.evidence_digest)
        _timestamp("decided_at", self.decided_at)
        if self.effective_oversight_determined:
            raise GovernanceError("oversight decision evidence does not determine effective human oversight")

    @property
    def artifact_digest(self) -> str:
        return sha256_digest(self)


def create_human_oversight_decision(
    requirement: HumanOversightRequirement,
    *,
    reviewer_id: str,
    reviewer_role: str,
    decision: HumanOversightDecisionKind,
    rationale: str,
    evidence_digest: str,
    decided_at: int,
) -> HumanOversightDecision:
    if requirement.required and reviewer_role not in requirement.required_roles:
        raise GovernanceError("reviewer role does not satisfy human oversight requirement")
    return HumanOversightDecision(
        requirement_digest=requirement.evidence_digest,
        reviewer_id=reviewer_id,
        reviewer_role=reviewer_role,
        decision=decision,
        rationale=rationale,
        evidence_digest=evidence_digest,
        decided_at=decided_at,
    )


@dataclass(frozen=True, slots=True)
class GenAIRevalidationEvidence:
    institution_id: str
    model_id: str
    before_overlay_digest: str
    after_overlay_digest: str
    triggers: tuple[GenAIRevalidationTrigger, ...]
    revalidation_requirement_digest: str
    rationale: str

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("before_overlay_digest", self.before_overlay_digest)
        _digest("after_overlay_digest", self.after_overlay_digest)
        _digest("revalidation_requirement_digest", self.revalidation_requirement_digest)
        if self.before_overlay_digest == self.after_overlay_digest:
            raise GovernanceError("GenAI revalidation evidence requires changed overlay state")
        if not self.triggers or len(self.triggers) != len(set(self.triggers)):
            raise GovernanceError("GenAI revalidation triggers must be non-empty and unique")
        if any(not isinstance(trigger, GenAIRevalidationTrigger) for trigger in self.triggers):
            raise GovernanceError("GenAI revalidation triggers must use governed enum values")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def derive_genai_revalidation(
    record: ModelRecord,
    version: ModelVersion,
    policy: RiskPolicyProfile,
    before_overlay: GenAIOverlaySnapshot,
    after_overlay: GenAIOverlaySnapshot,
    *,
    triggers: Iterable[GenAIRevalidationTrigger],
    rationale: str,
) -> tuple[RevalidationRequirement, GenAIRevalidationEvidence]:
    if (record.institution_id, record.model_id, version.version_id) != (
        after_overlay.institution_id, after_overlay.model_id, after_overlay.version_id
    ):
        raise GovernanceError("current model/version does not match after GenAI overlay")
    if (before_overlay.institution_id, before_overlay.model_id) != (record.institution_id, record.model_id):
        raise GovernanceError("before GenAI overlay belongs to different institution/model")
    ordered = tuple(sorted(tuple(triggers), key=lambda item: item.value))
    if not ordered or len(ordered) != len(set(ordered)):
        raise GovernanceError("GenAI revalidation requires unique explicit triggers")
    before_state = sha256_digest({
        "model_record_digest": record.evidence_digest,
        "model_version_digest": version.evidence_digest,
        "risk_policy_digest": policy.evidence_digest,
        "genai_overlay_digest": before_overlay.evidence_digest,
    })
    after_state = sha256_digest({
        "model_record_digest": record.evidence_digest,
        "model_version_digest": version.evidence_digest,
        "risk_policy_digest": policy.evidence_digest,
        "genai_overlay_digest": after_overlay.evidence_digest,
        "genai_triggers": [item.value for item in ordered],
    })
    requirement = RevalidationRequirement(
        institution_id=record.institution_id,
        model_id=record.model_id,
        before_state_digest=before_state,
        after_state_digest=after_state,
        triggers=(RevalidationTrigger.CONTROL_DETERIORATION,),
        rationale=_text("rationale", rationale),
    )
    evidence = GenAIRevalidationEvidence(
        institution_id=record.institution_id,
        model_id=record.model_id,
        before_overlay_digest=before_overlay.evidence_digest,
        after_overlay_digest=after_overlay.evidence_digest,
        triggers=ordered,
        revalidation_requirement_digest=requirement.evidence_digest,
        rationale=rationale,
    )
    return requirement, evidence
