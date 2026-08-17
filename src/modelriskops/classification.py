from __future__ import annotations

from .models import ClassificationPolicy, ModelClassification, ModelRecord, ModelRiskAssessment, RiskTier, _RISK_ORDER, max_risk


class ModelRiskClassifier:
    def classify(
        self,
        model: ModelRecord,
        assessment: ModelRiskAssessment,
        policy: ClassificationPolicy,
        *,
        classified_at: str,
    ) -> ModelClassification:
        if len({model.institution_id, assessment.institution_id, policy.institution_id}) != 1:
            raise ValueError("institution mismatch across model classification inputs")
        if assessment.model_id != model.model_id:
            raise ValueError("assessment does not bind the model")

        tier = assessment.impact_tier
        reasons = [f"impact_tier:{assessment.impact_tier.value}"]
        checks = (
            (assessment.customer_decisioning, policy.customer_decisioning_min_tier, "customer_decisioning"),
            (assessment.regulatory_reporting, policy.regulatory_reporting_min_tier, "regulatory_reporting"),
            (assessment.generative_ai, policy.generative_ai_min_tier, "generative_ai"),
            (assessment.external_dependency, policy.external_dependency_min_tier, "external_dependency"),
            (assessment.personal_data, policy.personal_data_min_tier, "personal_data"),
        )
        for active, minimum, reason in checks:
            if active:
                new_tier = max_risk(tier, minimum)
                if _RISK_ORDER[new_tier] > _RISK_ORDER[tier]:
                    reasons.append(f"escalated:{reason}:{minimum.value}")
                else:
                    reasons.append(f"factor:{reason}")
                tier = new_tier

        independent = _RISK_ORDER[tier] >= _RISK_ORDER[policy.independent_validation_min_tier]
        if independent:
            reasons.append("independent_validation_required")

        return ModelClassification(
            institution_id=model.institution_id,
            model_id=model.model_id,
            model_digest=model.artifact_digest,
            assessment_digest=assessment.artifact_digest,
            policy_digest=policy.artifact_digest,
            risk_tier=tier,
            reason_codes=tuple(reasons),
            independent_validation_required=independent,
            classified_at=classified_at,
        )
