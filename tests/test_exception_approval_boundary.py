import pytest

from modelriskops import GovernanceError, create_exception
from tests.test_dossier import approved_chain


@pytest.mark.parametrize(
    "requirement_id",
    ("senior_risk_approval", "executive_risk_acceptance"),
)
def test_accountable_approval_roles_are_non_exceptionable(requirement_id: str) -> None:
    _, version, _, risk, *_ = approved_chain()
    with pytest.raises(GovernanceError, match="non-exceptionable"):
        create_exception(
            version,
            risk,
            exception_id=f"EX-{requirement_id}",
            waived_requirement_ids=(requirement_id,),
            owner_id="risk-owner",
            rationale="Approval roles must not be bypassed",
            compensating_controls=("manual-review",),
            issued_at=100,
            expires_at=200,
        )
