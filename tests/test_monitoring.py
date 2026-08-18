from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from modelriskops import (
    GovernanceError,
    MetricDefinition,
    MetricKind,
    MetricStatus,
    ModelVersion,
    MonitoringLevel,
    MonitoringObservation,
    MonitoringState,
    RevalidationTrigger,
    RiskDecision,
    RiskTier,
    ThresholdDirection,
    assess_monitoring,
    build_monitoring_plan,
    canonical_json,
    derive_monitoring_revalidation,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def version() -> ModelVersion:
    return ModelVersion(
        institution_id="bank-a",
        model_id="credit-model",
        version_id="2026-08",
        artifact_digest=digest("artifact"),
        code_digest=digest("code"),
        data_digest=digest("data"),
        config_digest=digest("config"),
        provenance_source="controlled-build",
    )


def risk(model_version: ModelVersion, *, enhanced: bool = False) -> RiskDecision:
    requirements = (
        ("accountable_owner", "independent_validation", "enhanced_monitoring")
        if enhanced
        else ("accountable_owner", "monitoring_plan")
    )
    tier = RiskTier.CRITICAL if enhanced else RiskTier.HIGH
    return RiskDecision(
        institution_id=model_version.institution_id,
        model_id=model_version.model_id,
        version_id=model_version.version_id,
        model_digest=digest("model-record"),
        model_version_digest=model_version.evidence_digest,
        policy_digest=digest("risk-policy"),
        inherent_score=60,
        inherent_tier=tier,
        control_credit=5,
        residual_score=55,
        residual_tier=tier,
        contributions=(),
        requirements=requirements,
    )


def definitions() -> tuple[MetricDefinition, ...]:
    return (
        MetricDefinition(
            metric_id="accuracy",
            kind=MetricKind.PERFORMANCE,
            direction=ThresholdDirection.BELOW_IS_WORSE,
            warning_threshold=0.90,
            breach_threshold=0.80,
            min_samples=100,
        ),
        MetricDefinition(
            metric_id="psi",
            kind=MetricKind.DATA_DRIFT,
            direction=ThresholdDirection.ABOVE_IS_WORSE,
            warning_threshold=0.20,
            breach_threshold=0.40,
            min_samples=100,
            reference_digest=digest("training-baseline"),
        ),
    )


def plan_and_risk():
    model_version = version()
    decision = risk(model_version)
    plan = build_monitoring_plan(
        model_version,
        decision,
        definitions(),
        cadence_seconds=60,
        max_staleness_seconds=180,
    )
    return model_version, decision, plan


def observation(plan, metric_id: str, value: float, *, observed_at: int = 200, samples: int = 200):
    return MonitoringObservation(
        monitoring_plan_digest=plan.evidence_digest,
        metric_id=metric_id,
        window_start=100,
        window_end=190,
        observed_at=observed_at,
        value=value,
        sample_size=samples,
        source_evidence_digest=digest(f"source-{metric_id}-{value}-{observed_at}-{samples}"),
    )


def test_drift_metric_requires_exact_reference_digest():
    with pytest.raises(GovernanceError, match="reference_digest"):
        MetricDefinition(
            metric_id="psi",
            kind=MetricKind.DATA_DRIFT,
            direction=ThresholdDirection.ABOVE_IS_WORSE,
            warning_threshold=0.2,
            breach_threshold=0.4,
            min_samples=100,
        )


def test_runtime_integer_types_match_schema_contracts():
    with pytest.raises(GovernanceError, match="min_samples"):
        MetricDefinition(
            metric_id="accuracy",
            kind=MetricKind.PERFORMANCE,
            direction=ThresholdDirection.BELOW_IS_WORSE,
            warning_threshold=0.9,
            breach_threshold=0.8,
            min_samples=100.0,
        )

    model_version = version()
    decision = risk(model_version)
    with pytest.raises(GovernanceError, match="cadence_seconds"):
        build_monitoring_plan(
            model_version,
            decision,
            definitions(),
            cadence_seconds=60.0,
            max_staleness_seconds=180,
        )


def test_monitoring_plan_binds_exact_version_and_risk_and_sorts_metrics():
    model_version, decision, plan = plan_and_risk()
    assert plan.model_version_digest == model_version.evidence_digest
    assert plan.risk_decision_digest == decision.evidence_digest
    assert plan.monitoring_level is MonitoringLevel.STANDARD
    assert tuple(item.metric_id for item in plan.metrics) == ("accuracy", "psi")


def test_enhanced_monitoring_requires_three_metrics_and_drift():
    model_version = version()
    decision = risk(model_version, enhanced=True)
    with pytest.raises(GovernanceError, match="enhanced monitoring"):
        build_monitoring_plan(
            model_version,
            decision,
            definitions(),
            cadence_seconds=60,
            max_staleness_seconds=180,
        )


def test_healthy_and_warning_assessments_are_deterministic():
    model_version, decision, plan = plan_and_risk()
    healthy_observations = (
        observation(plan, "psi", 0.10),
        observation(plan, "accuracy", 0.95),
    )
    first = assess_monitoring(plan, model_version, decision, healthy_observations, as_of=250)
    second = assess_monitoring(plan, model_version, decision, reversed(healthy_observations), as_of=250)
    assert first == second
    assert first.state is MonitoringState.HEALTHY
    assert first.revalidation_required is False
    assert {item.status for item in first.metric_assessments} == {MetricStatus.PASS}

    warning = assess_monitoring(
        plan,
        model_version,
        decision,
        (observation(plan, "accuracy", 0.95), observation(plan, "psi", 0.30)),
        as_of=250,
    )
    assert warning.state is MonitoringState.DEGRADED
    assert warning.revalidation_required is False


def test_breach_creates_monitoring_deterioration_revalidation_requirement():
    model_version, decision, plan = plan_and_risk()
    assessment = assess_monitoring(
        plan,
        model_version,
        decision,
        (observation(plan, "accuracy", 0.95), observation(plan, "psi", 0.50)),
        as_of=250,
    )
    assert assessment.state is MonitoringState.BREACHED
    assert assessment.revalidation_required is True
    requirement = derive_monitoring_revalidation(assessment, model_version, decision)
    assert requirement.triggers == (RevalidationTrigger.MONITORING_DETERIORATION,)
    assert "psi:breach" in requirement.rationale
    assert requirement.before_state_digest != requirement.after_state_digest


def test_missing_stale_and_insufficient_evidence_fail_closed():
    model_version, decision, plan = plan_and_risk()

    missing = assess_monitoring(
        plan,
        model_version,
        decision,
        (observation(plan, "accuracy", 0.95),),
        as_of=250,
    )
    assert missing.state is MonitoringState.INCOMPLETE
    assert missing.revalidation_required is True
    assert any(item.status is MetricStatus.MISSING for item in missing.metric_assessments)

    stale = assess_monitoring(
        plan,
        model_version,
        decision,
        (observation(plan, "accuracy", 0.95, observed_at=200), observation(plan, "psi", 0.10, observed_at=200)),
        as_of=500,
    )
    assert stale.state is MonitoringState.INCOMPLETE
    assert {item.status for item in stale.metric_assessments} == {MetricStatus.STALE}

    insufficient = assess_monitoring(
        plan,
        model_version,
        decision,
        (observation(plan, "accuracy", 0.95, samples=10), observation(plan, "psi", 0.10, samples=10)),
        as_of=250,
    )
    assert insufficient.state is MonitoringState.INCOMPLETE
    assert {item.status for item in insufficient.metric_assessments} == {MetricStatus.INSUFFICIENT_SAMPLES}


def test_conflicting_latest_observations_and_stale_risk_fail_closed():
    model_version, decision, plan = plan_and_risk()
    with pytest.raises(GovernanceError, match="conflicting latest"):
        assess_monitoring(
            plan,
            model_version,
            decision,
            (
                observation(plan, "accuracy", 0.95),
                observation(plan, "accuracy", 0.70),
                observation(plan, "psi", 0.10),
            ),
            as_of=250,
        )

    changed_risk = replace(decision, residual_score=decision.residual_score + 1)
    with pytest.raises(GovernanceError, match="stale for risk decision"):
        assess_monitoring(
            plan,
            model_version,
            changed_risk,
            (observation(plan, "accuracy", 0.95), observation(plan, "psi", 0.10)),
            as_of=250,
        )


def test_monitoring_artifacts_validate_against_release_schemas():
    model_version, decision, plan = plan_and_risk()
    accuracy = observation(plan, "accuracy", 0.95)
    drift = observation(plan, "psi", 0.10)
    assessment = assess_monitoring(
        plan,
        model_version,
        decision,
        (accuracy, drift),
        as_of=250,
    )

    root = Path(__file__).resolve().parents[1]
    cases = (
        ("monitoring-plan.schema.json", plan),
        ("monitoring-observation.schema.json", drift),
        ("monitoring-assessment.schema.json", assessment),
    )
    for schema_name, artifact in cases:
        schema = json.loads((root / "schemas" / schema_name).read_text())
        payload = json.loads(canonical_json(artifact))
        jsonschema.Draft202012Validator(schema).validate(payload)
