from dataclasses import replace

import pytest

from modelriskops import (
    GovernanceError,
    assess_genai_evaluation,
    build_genai_governance_dossier,
)
from tests.test_dossier import build_approved_dossier
from tests.test_genai import evaluation_fixture, observations


def test_genai_evaluation_rejects_pre_plan_time_and_observations() -> None:
    *_, overlay, plan = evaluation_fixture()
    with pytest.raises(GovernanceError, match="cannot predate evaluation plan"):
        assess_genai_evaluation(plan, overlay, observations(plan), evaluated_at=100)

    early = tuple(replace(item, observed_at=100) for item in observations(plan))
    with pytest.raises(GovernanceError, match="observation cannot predate"):
        assess_genai_evaluation(plan, overlay, early, evaluated_at=160)


def test_genai_dossier_rejects_plan_bound_to_different_model_version_digest() -> None:
    _, _, _, foundation, prompt, rag, use_case, overlay, plan = evaluation_fixture()
    assessment = assess_genai_evaluation(plan, overlay, observations(plan), evaluated_at=160)
    stale_plan = replace(plan, model_version_digest="f" * 64)
    with pytest.raises(GovernanceError, match="stale for base dossier model version"):
        build_genai_governance_dossier(
            build_approved_dossier(),
            foundation,
            prompt,
            use_case,
            overlay,
            stale_plan,
            assessment,
            rag=rag,
        )
