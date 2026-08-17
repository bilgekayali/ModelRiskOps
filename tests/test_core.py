import unittest

from modelriskops.classification import ModelRiskClassifier
from modelriskops.models import ClassificationPolicy, LifecycleStatus, ModelFamily, ModelRecord, ModelRiskAssessment, RiskTier
from modelriskops.registry import ModelRegistry


class ModelRiskCoreTests(unittest.TestCase):
    def model(self, institution="bank-a"):
        return ModelRecord(
            institution_id=institution,
            model_id="credit-001",
            name="Credit Decision Model",
            family=ModelFamily.MACHINE_LEARNING,
            primary_use="credit decision support",
            owner_id="owner-1",
            business_unit="risk",
            lifecycle_status=LifecycleStatus.VALIDATION,
            model_version="1.2.0",
            production_use=False,
            registered_at="2026-08-17T12:00:00Z",
        )

    def test_registry_is_tenant_scoped(self):
        registry = ModelRegistry()
        registry.register(self.model("bank-a"))
        registry.register(self.model("bank-b"))
        self.assertEqual(len(registry.list_for_institution("bank-a")), 1)
        self.assertEqual(len(registry.list_for_institution("bank-b")), 1)

    def test_classifier_escalates_transparently(self):
        model = self.model()
        assessment = ModelRiskAssessment(
            institution_id="bank-a",
            model_id=model.model_id,
            impact_tier=RiskTier.MODERATE,
            customer_decisioning=True,
            regulatory_reporting=False,
            generative_ai=False,
            external_dependency=False,
            personal_data=True,
            assessed_at="2026-08-17T12:01:00Z",
        )
        result = ModelRiskClassifier().classify(model, assessment, ClassificationPolicy(institution_id="bank-a"), classified_at="2026-08-17T12:02:00Z")
        self.assertEqual(result.risk_tier, RiskTier.HIGH)
        self.assertTrue(result.independent_validation_required)
        self.assertIn("escalated:customer_decisioning:high", result.reason_codes)

    def test_cross_tenant_classification_fails(self):
        model = self.model("bank-a")
        assessment = ModelRiskAssessment("bank-b", model.model_id, RiskTier.LOW, False, False, False, False, False, "2026-08-17T12:01:00Z")
        with self.assertRaises(ValueError):
            ModelRiskClassifier().classify(model, assessment, ClassificationPolicy(institution_id="bank-a"), classified_at="2026-08-17T12:02:00Z")

    def test_digest_is_deterministic(self):
        self.assertEqual(self.model().artifact_digest, self.model().artifact_digest)


if __name__ == "__main__":
    unittest.main()
