import pytest

from modelriskops import (
    FindingSeverity,
    FindingStatus,
    GovernanceError,
    TestStatus,
    ValidationConclusion,
    ValidationDomain,
    ValidationFinding,
    ValidationPlan,
    ValidationTest,
    resolve_validation,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64


def test_remediated_finding_requires_remediation_evidence() -> None:
    with pytest.raises(GovernanceError, match="require remediation evidence"):
        ValidationFinding(
            finding_id="F-remediated",
            test_id="optional-robustness",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.REMEDIATED,
            evidence_digest=D1,
            description="Owner marked the issue remediated.",
        )


def test_optional_failed_test_cannot_resolve_to_unconditional_pass() -> None:
    plan = ValidationPlan(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id="2026.08.1",
        model_digest=D1,
        model_version_digest=D2,
        risk_decision_digest=D3,
        validator_id="independent-validator",
        validator_role="model-validation",
        independent_from_owner=True,
        tests=(
            ValidationTest(
                test_id="mandatory-concept",
                domain=ValidationDomain.CONCEPTUAL_SOUNDNESS,
                mandatory=True,
                status=TestStatus.PASS,
                evidence_digest=D4,
            ),
            ValidationTest(
                test_id="optional-robustness",
                domain=ValidationDomain.ROBUSTNESS,
                mandatory=False,
                status=TestStatus.FAIL,
                evidence_digest=D4,
            ),
        ),
    )
    resolution = resolve_validation(plan, ())
    assert resolution.conclusion is ValidationConclusion.PASS_WITH_CONDITIONS
