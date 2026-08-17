# ModelRiskOps

**Evidence-backed model risk governance for regulated financial institutions.**

## Summary

ModelRiskOps is an open-source reference architecture for governing analytical, statistical, machine-learning, and AI models through inventory, risk classification, independent validation, approval, monitoring, change control, and retirement.

Current development milestone: **v0.1.0 — Model Inventory and Classification**.

The project is not a model-training framework, automated model validator, regulatory certification product, or substitute for independent expert judgement.

## Purpose

Model risk is broader than predictive accuracy. Institutions need durable evidence of which models exist, who owns them, how material they are, which risk factors apply, when independent validation is required, what changed, and which lifecycle controls remain open.

v0.1 provides a deliberately offline inventory/classification boundary. Classification is deterministic but policy-configurable; it does not infer regulatory applicability automatically.

## v0.1 control flow

```text
ModelRecord + ModelRiskAssessment + ClassificationPolicy
                         |
                         v
                ModelRiskClassifier
                         |
                         v
               ModelClassification
```

## Safety and governance baseline

- institution-scoped registry;
- deterministic canonical JSON + SHA-256 evidence bindings;
- no model execution or training;
- no automatic model validation or approval;
- no network/process capability in the v0.1 core;
- independent-validation requirement is a governance output, not proof that validation occurred;
- no supervisory, legal, or standards-certification claim.

## Standards posture

Design inputs include:

- Federal Reserve SR 26-2 — Revised Guidance on Model Risk Management (2026): https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- Regulation (EU) 2024/1689 — EU Artificial Intelligence Act: https://eur-lex.europa.eu/eli/reg/2024/1689/oj

## Repository map

```text
src/modelriskops/models.py          immutable inventory/risk artifacts
src/modelriskops/registry.py        institution-scoped model registry
src/modelriskops/classification.py  deterministic policy-based classification
schemas/                            strict machine-readable contracts
tests/                              regression and contract tests
docs/                               architecture and roadmap
```

## Roadmap

`v0.1 inventory/classification → v0.2 validation evidence → v0.3 approval/exceptions → v0.4 monitoring/change → v0.5 AI/GenAI overlays → assurance/hardening → v1.0`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache License 2.0.
