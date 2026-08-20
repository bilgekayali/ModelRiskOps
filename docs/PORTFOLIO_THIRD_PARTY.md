# ModelRiskOps v0.5 — Portfolio and Third-Party Model Risk

## Purpose

ModelRiskOps v0.5 adds an offline, evidence-backed portfolio and third-party model-risk boundary over the existing model inventory, risk classification, validation, monitoring, signed change-control and AI/GenAI governance layers.

The boundary answers a limited governance question:

> Given institution-supplied model exposure weights, current model-risk evidence, explicit third-party dependencies and current provider due-diligence/contract evidence, what concentration, substitutability and exit-readiness findings are reproducible from those represented inputs?

It does **not** discover vendors, score vendor safety, assess legal outsourcing status, infer financial resilience, inspect live provider services or determine regulatory compliance.

## Provider profiles

`ThirdPartyProviderProfile` is institution-scoped and append-only/versioned. It binds:

- provider identity and accountable owner;
- service jurisdictions supplied by the institution;
- due-diligence evidence;
- contract evidence;
- security-assurance evidence;
- financial-resilience evidence; and
- explicit due-diligence and contract expiry times.

Provider evidence is represented evidence only. A digest does not prove that a provider is secure, solvent, legally acceptable or contractually sufficient.

## Third-party model dependencies

`ThirdPartyModelDependency` binds one exact current `ModelVersion` to one exact current provider profile and service identity. It also binds the provider's represented model identity/version and an exact `provider_version_evidence_digest`, so a vendor model/version change requires new dependency evidence rather than being hidden behind a stable provider or service name.

The dependency carries explicit institution-owned judgments for:

- materiality: `non_material`, `material`, `critical`;
- substitutability: `high`, `moderate`, `low`, `none`; and
- represented provider data-access level: `none`, `non_sensitive`, `personal`, `sensitive`.

Dependencies are append-only/versioned. A provider-profile or represented provider-model/version update does not silently rewrite an existing dependency. The old dependency remains historical evidence but fails current-use validation when its current binding has been superseded.

## Exit and transition evidence

`ThirdPartyExitPlan` binds to one exact dependency digest and carries transition-strategy, portability and validation-plan evidence plus a bounded maximum exit duration.

Material and critical dependencies require a current exit plan under the v0.5 policy contract. Critical dependencies additionally require represented exit-plan test evidence. An assessment cannot use an exit plan whose `created_at` is later than `assessed_at`, and a critical dependency cannot use test evidence whose `tested_at` is later than `assessed_at`. Future evidence therefore cannot retroactively satisfy an earlier portfolio assessment.

ModelRiskOps records and verifies these artifacts; it does not execute an exit, portability test or migration.

## Portfolio snapshot

`PortfolioSnapshot` binds:

- the exact current `InventoryRegistry.snapshot_digest()`;
- one current model version per portfolio position;
- the exact `RiskDecision` digest and residual risk tier for each position;
- exact current third-party dependency digests; and
- institution-supplied exposure weights that must total exactly **10,000 basis points**.

The weights are governance inputs. ModelRiskOps does not infer capital exposure, revenue dependency, loss magnitude or economic materiality from production data.

## Deterministic assessment

`PortfolioRiskRegistry.assess_portfolio()` produces one of:

- `healthy` — no represented threshold, currentness or exit-readiness finding;
- `degraded` — warning-level provider concentration or low/none substitutability for a material/critical dependency;
- `breached` — an institution-owned provider-concentration or high/critical exposure limit is exceeded;
- `incomplete` — required evidence is missing, expired or not yet effective at the represented assessment time.

State precedence is fail-closed:

`incomplete > breached > degraded > healthy`

A provider's portfolio exposure counts a model's exposure weight once for that provider even when the model has multiple services from the same provider. Dependency count is retained separately so duplicate service relationships remain visible without double-counting model exposure.

`critical_provider_ids` explicitly identifies providers supporting at least one dependency classified by the institution as `critical`. This is a derived governance label from represented dependency materiality; it is not a legal or supervisory designation of a critical ICT/provider entity.

The built-in default concentration thresholds are reference/test defaults only. They are not regulatory thresholds and should be replaced by institution-approved policy values for real use.

## Currentness and historical evidence

Provider profiles, dependencies, exit plans and snapshots are immutable historical evidence.

For **new** artifacts, the registry requires current model inventory, current provider profile and current dependency state. A stale provider or inventory cannot be used to create new current-use portfolio evidence.

For an **exact historical retry**, the same immutable identity plus the same digest is idempotently accepted even if later governance drift has occurred. The retry does not restore current eligibility. `assert_dependency_current()` and `assert_snapshot_current()` still fail closed against superseded provider/dependency/inventory state.

This distinction preserves audit history without allowing old evidence to masquerade as current.

## Evidence package

`PortfolioEvidencePackage` binds the exact:

- portfolio snapshot;
- portfolio risk policy;
- reproduced portfolio assessment;
- provider-profile digests;
- dependency digests; and
- exit-plan digests.

Offline verification rebuilds the package from current registered evidence. A rehashed or substituted assessment/package that does not reproduce fails closed.

## Design inputs

The v0.5 design uses the following as governance inputs, not automatic compliance rules:

- Federal Reserve **SR 26-2 — Revised Guidance on Model Risk Management** (2026), including vendor-model understanding, validation and ongoing monitoring considerations;
- NIST **AI 600-1 — Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile**, including third-party GAI resource/value-chain risk and reassessment considerations; and
- Regulation (EU) **2024/1689** (EU AI Act), including provider/general-purpose AI documentation and information-sharing context.

Applicability, legal interpretation, supervisory expectations and acceptable concentration thresholds remain institution- and jurisdiction-specific human decisions.

## Explicit non-claims

ModelRiskOps v0.5 does not itself establish:

- that a third-party provider or model is safe, approved, financially resilient or trustworthy;
- that a provider classified here as supporting a critical model dependency is legally or regulatorily a "critical" provider;
- the legal materiality of an outsourcing or third-party arrangement;
- DORA, EU AI Act, SR 26-2 or other regulatory compliance;
- contractual sufficiency, enforceability or exit rights;
- objective provider concentration or economic exposure beyond institution-supplied portfolio weights;
- successful provider substitution, portability, exit or migration;
- live provider availability, security posture or operational performance;
- authenticity of external due-diligence/contract/security/financial/provider-version evidence merely because its digest is bound; or
- production fitness, certification, supervisory acceptance or legal advice.

The portfolio core remains offline and does not train, execute, call, probe or monitor models or provider services.
