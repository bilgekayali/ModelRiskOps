# ModelRiskOps Architecture

## v0.1 boundary

v0.1 is an offline model inventory and classification core. It records governed model metadata, binds a separate risk assessment to the exact model, applies an institution-scoped classification policy, and emits deterministic classification evidence.

It does not train, execute, benchmark, validate, approve, or monitor a model.

```text
ModelRecord + ModelRiskAssessment + ClassificationPolicy
                         |
                         v
                ModelRiskClassifier
                         |
                         v
               ModelClassification
```

Classification thresholds are explicit policy inputs. ModelRiskOps does not infer regulatory status from a model type or use case.

## Trust model

Model owners, inventory administrators, and risk assessors are external accountable actors in v0.1. Supplied metadata and assessments are governance inputs, not independently verified facts.

## Standards posture

The architecture is informed by Federal Reserve SR 26-2, NIST AI RMF, and the EU AI Act. These are design inputs only; v0.1 does not claim supervisory, legal, or standards compliance.
