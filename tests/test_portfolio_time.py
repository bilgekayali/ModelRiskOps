from dataclasses import replace

from modelriskops.portfolio import PortfolioAssessmentState
from tests.test_portfolio import PortfolioFixture, permissive_policy


def test_material_exit_plan_created_after_assessment_cannot_satisfy_readiness() -> None:
    fx = PortfolioFixture()
    future_plan = replace(
        fx.exit_b,
        plan_version=2,
        created_at=200,
    )
    fx.registry.register_exit_plan(future_plan)
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=180)
    assert assessment.state is PortfolioAssessmentState.INCOMPLETE
    assert "exit_plan_not_effective_at_assessment:vendor-service-b" in assessment.findings


def test_critical_exit_test_after_assessment_cannot_satisfy_readiness() -> None:
    fx = PortfolioFixture()
    future_test = replace(
        fx.exit_a,
        plan_version=2,
        created_at=160,
        tested_at=200,
        test_evidence_digest="f" * 64,
    )
    fx.registry.register_exit_plan(future_test)
    assessment = fx.registry.assess_portfolio(fx.snapshot, permissive_policy(), assessed_at=180)
    assert assessment.state is PortfolioAssessmentState.INCOMPLETE
    assert "critical_exit_test_not_effective_at_assessment:vendor-service-a" in assessment.findings
