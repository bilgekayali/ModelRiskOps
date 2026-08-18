import json
from pathlib import Path

import jsonschema

from modelriskops import (
    ChangeMateriality,
    GenAIRevalidationTrigger,
    HumanOversightDecisionKind,
    assess_genai_evaluation,
    canonical_json,
    create_genai_model_change_proposal,
    create_human_oversight_decision,
    create_human_oversight_requirement,
)
from tests.test_genai import D5, evaluation_fixture, observations, overlay_fixture


ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def test_real_genai_overlay_artifacts_match_strict_schemas() -> None:
    _, _, _, foundation, prompt, rag, use_case, overlay, plan = evaluation_fixture()
    jsonschema.validate(payload(foundation), schema("foundation-model-dependency.schema.json"))
    jsonschema.validate(payload(prompt), schema("prompt-policy.schema.json"))
    jsonschema.validate(payload(rag), schema("rag-configuration.schema.json"))
    jsonschema.validate(payload(use_case), schema("genai-use-case.schema.json"))
    jsonschema.validate(payload(overlay), schema("genai-overlay-snapshot.schema.json"))
    jsonschema.validate(payload(plan), schema("genai-evaluation-plan.schema.json"))


def test_real_genai_evaluation_and_oversight_match_strict_schemas() -> None:
    *_, use_case, overlay, plan = evaluation_fixture()
    observation_set = observations(plan)
    for observation in observation_set:
        jsonschema.validate(payload(observation), schema("genai-evaluation-observation.schema.json"))
    assessment = assess_genai_evaluation(plan, overlay, observation_set, evaluated_at=160)
    jsonschema.validate(payload(assessment), schema("genai-evaluation-assessment.schema.json"))

    requirement = create_human_oversight_requirement(
        use_case,
        plan,
        required=True,
        required_roles=("human_reviewer",),
        rationale="review required",
    )
    decision = create_human_oversight_decision(
        requirement,
        reviewer_id="reviewer-1",
        reviewer_role="human_reviewer",
        decision=HumanOversightDecisionKind.ACCEPT,
        rationale="reviewed",
        evidence_digest=D5,
        decided_at=170,
    )
    jsonschema.validate(payload(requirement), schema("human-oversight-requirement.schema.json"))
    jsonschema.validate(payload(decision), schema("human-oversight-decision.schema.json"))


def test_real_genai_revalidation_evidence_matches_strict_schema() -> None:
    record, version, policy, *_, before_overlay = overlay_fixture(prompt_digest="2" * 64)
    *_, after_overlay = overlay_fixture(prompt_digest="8" * 64)
    _, _, evidence = create_genai_model_change_proposal(
        record,
        record,
        version,
        version,
        policy,
        policy,
        before_overlay,
        after_overlay,
        change_id="GENAI-CHANGE-1",
        materiality=ChangeMateriality.MATERIAL,
        materiality_owner_id="ai-risk-owner",
        materiality_rationale="accountable materiality decision",
        proposed_at=180,
        triggers=(GenAIRevalidationTrigger.PROMPT_POLICY,),
        revalidation_rationale="prompt policy changed",
    )
    jsonschema.validate(payload(evidence), schema("genai-revalidation-evidence.schema.json"))
