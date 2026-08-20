from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from modelriskops import canonical_json
from modelriskops.assurance import (
    Applicability,
    AssuranceApplicabilityAssertion,
    AssuranceCrosswalkEntry,
    AssuranceEvidenceReference,
    AssuranceEvidenceRegistry,
    AssuranceFramework,
    AssuranceMappingProfile,
    AssuranceScope,
    AssuranceSubjectKind,
    EUAIActRole,
    EvidenceCoverage,
)
from modelriskops.models import GovernanceError


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64


def fixture(*, complete: bool = True):
    registry = AssuranceEvidenceRegistry()
    sr = AssuranceMappingProfile(
        institution_id="bank-demo",
        profile_id="sr-26-2",
        profile_version=1,
        framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
        framework_version="SR 26-2",
        reference_ids=("inventory_governance", "model_validation"),
        source_document_digest=D1,
        owner_id="model-risk-owner",
        registered_at=90,
    )
    eu = AssuranceMappingProfile(
        institution_id="bank-demo",
        profile_id="eu-ai-act",
        profile_version=1,
        framework=AssuranceFramework.EU_AI_ACT,
        framework_version="2024/1689@2026-07-27",
        reference_ids=("article-26-deployer-obligations",),
        source_document_digest=D2,
        owner_id="legal-ai-owner",
        registered_at=91,
    )
    registry.register_mapping_profile(sr)
    registry.register_mapping_profile(eu)
    scope = AssuranceScope(
        institution_id="bank-demo",
        scope_id="model-a-v1-assurance",
        scope_version=1,
        subject_kind=AssuranceSubjectKind.MODEL_VERSION,
        subject_id="model-a",
        subject_version="1",
        subject_artifact_digest=D3,
        context_digest=D4,
        owner_id="model-owner",
        mapping_profile_digests=tuple(sorted((sr.evidence_digest, eu.evidence_digest))),
        recorded_at=100,
    )
    registry.register_scope(scope)

    assertions = (
        AssuranceApplicabilityAssertion(
            assertion_id="sr-inventory-app",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="inventory_governance",
            applicability=Applicability.APPLICABLE,
            eu_ai_act_roles=(),
            confirmation_basis="human applicability assessment",
            confirmed_by_id="model-risk-reviewer",
            confirmed_at=110,
        ),
        AssuranceApplicabilityAssertion(
            assertion_id="sr-validation-app",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="model_validation",
            applicability=Applicability.APPLICABLE,
            eu_ai_act_roles=(),
            confirmation_basis="human applicability assessment",
            confirmed_by_id="model-risk-reviewer",
            confirmed_at=111,
        ),
        AssuranceApplicabilityAssertion(
            assertion_id="eu-deployer-app",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.EU_AI_ACT,
            framework_version="2024/1689@2026-07-27",
            reference_id="article-26-deployer-obligations",
            applicability=Applicability.APPLICABLE,
            eu_ai_act_roles=(EUAIActRole.DEPLOYER,),
            confirmation_basis="human operator-role assessment",
            confirmed_by_id="legal-reviewer",
            confirmed_at=112,
        ),
    )
    for assertion in assertions:
        registry.register_applicability(assertion)

    evidence = (
        AssuranceEvidenceReference(
            evidence_id="inventory-evidence",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            subject_artifact_digest=D5,
            artifact_type="governance_dossier",
            source_component="modelriskops.dossier",
            evidence_basis="exact governance dossier digest",
            registered_at=115,
        ),
        AssuranceEvidenceReference(
            evidence_id="validation-evidence",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            subject_artifact_digest=D6,
            artifact_type="validation_resolution",
            source_component="modelriskops.validation",
            evidence_basis="exact validation resolution digest",
            registered_at=116,
        ),
    )
    for item in evidence:
        registry.register_evidence(item)

    entries = (
        AssuranceCrosswalkEntry(
            entry_id="sr-inventory-map",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="inventory_governance",
            applicability_assertion_digest=assertions[0].evidence_digest,
            coverage=EvidenceCoverage.SUPPORTED,
            evidence_reference_digests=(evidence[0].evidence_digest,),
            mapping_rationale="inventory evidence supports represented governance reference",
            mapped_by_id="assurance-reviewer",
            mapped_at=120,
        ),
        AssuranceCrosswalkEntry(
            entry_id="sr-validation-map",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="model_validation",
            applicability_assertion_digest=assertions[1].evidence_digest,
            coverage=EvidenceCoverage.PARTIAL,
            evidence_reference_digests=(evidence[1].evidence_digest,),
            mapping_rationale="validation evidence is partial for represented reference",
            mapped_by_id="assurance-reviewer",
            mapped_at=121,
        ),
        AssuranceCrosswalkEntry(
            entry_id="eu-deployer-map",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.EU_AI_ACT,
            framework_version="2024/1689@2026-07-27",
            reference_id="article-26-deployer-obligations",
            applicability_assertion_digest=assertions[2].evidence_digest,
            coverage=EvidenceCoverage.GAP,
            evidence_reference_digests=(),
            mapping_rationale="human review identified a represented evidence gap",
            mapped_by_id="assurance-reviewer",
            mapped_at=122,
        ),
    )
    for item in entries[: (3 if complete else 2)]:
        registry.register_entry(item)
    return registry, sr, eu, scope, assertions, evidence, entries


def test_complete_package_is_closed_over_required_references_and_nonclaims() -> None:
    registry, sr, eu, scope, assertions, evidence, entries = fixture()
    package = registry.build_evidence_package(
        scope,
        package_id="pkg-1",
        assembled_by_id="assurance-owner",
        assembled_at=130,
    )
    registry.register_package(package)
    registry.verify_package(package)
    registry.assert_package_current(package)

    summaries = {item.framework: item for item in package.coverage_summaries}
    sr_summary = summaries[AssuranceFramework.FEDERAL_RESERVE_SR_26_2]
    assert sr_summary.required_reference_count == 2
    assert sr_summary.supported_count == 1
    assert sr_summary.partial_count == 1
    eu_summary = summaries[AssuranceFramework.EU_AI_ACT]
    assert eu_summary.gap_count == 1
    assert package.certification_claimed is False
    assert package.conformity_claimed is False
    assert package.legal_compliance_determined is False
    assert package.supervisory_acceptance_claimed is False
    assert package.requires_human_review is True


def test_package_rejects_cherry_picked_incomplete_crosswalk() -> None:
    registry, _, _, scope, *_ = fixture(complete=False)
    with pytest.raises(GovernanceError, match="exactly one crosswalk entry"):
        registry.build_evidence_package(
            scope,
            package_id="pkg-incomplete",
            assembled_by_id="assurance-owner",
            assembled_at=130,
        )


def test_framework_versions_are_pinned() -> None:
    with pytest.raises(GovernanceError, match="framework_version must be pinned"):
        AssuranceMappingProfile(
            institution_id="bank-demo",
            profile_id="sr",
            profile_version=1,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 11-7",
            reference_ids=("x",),
            source_document_digest=D1,
            owner_id="owner",
            registered_at=1,
        )


def test_eu_roles_are_human_confirmed_and_framework_scoped() -> None:
    registry, sr, eu, scope, *_ = fixture()
    with pytest.raises(GovernanceError, match="requires at least one"):
        AssuranceApplicabilityAssertion(
            assertion_id="bad-eu",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.EU_AI_ACT,
            framework_version="2024/1689@2026-07-27",
            reference_id="article-26-deployer-obligations",
            applicability=Applicability.APPLICABLE,
            eu_ai_act_roles=(),
            confirmation_basis="x",
            confirmed_by_id="human",
            confirmed_at=120,
        )
    with pytest.raises(GovernanceError, match="only valid"):
        AssuranceApplicabilityAssertion(
            assertion_id="bad-sr",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="inventory_governance",
            applicability=Applicability.APPLICABLE,
            eu_ai_act_roles=(EUAIActRole.DEPLOYER,),
            confirmation_basis="x",
            confirmed_by_id="human",
            confirmed_at=120,
        )


def test_coverage_semantics_fail_closed() -> None:
    registry, _, _, scope, assertions, evidence, _ = fixture()
    with pytest.raises(GovernanceError, match="requires evidence"):
        AssuranceCrosswalkEntry(
            entry_id="bad-supported",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="inventory_governance",
            applicability_assertion_digest=assertions[0].evidence_digest,
            coverage=EvidenceCoverage.SUPPORTED,
            evidence_reference_digests=(),
            mapping_rationale="x",
            mapped_by_id="human",
            mapped_at=120,
        )
    with pytest.raises(GovernanceError, match="must not carry"):
        AssuranceCrosswalkEntry(
            entry_id="bad-gap",
            institution_id="bank-demo",
            scope_digest=scope.evidence_digest,
            framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
            framework_version="SR 26-2",
            reference_id="inventory_governance",
            applicability_assertion_digest=assertions[0].evidence_digest,
            coverage=EvidenceCoverage.GAP,
            evidence_reference_digests=(evidence[0].evidence_digest,),
            mapping_rationale="x",
            mapped_by_id="human",
            mapped_at=120,
        )


def test_mapping_cannot_use_future_registered_evidence() -> None:
    registry, _, _, scope, assertions, *_ = fixture()
    future = AssuranceEvidenceReference(
        evidence_id="future",
        institution_id="bank-demo",
        scope_digest=scope.evidence_digest,
        subject_artifact_digest=D1,
        artifact_type="future",
        source_component="test",
        evidence_basis="future evidence",
        registered_at=200,
    )
    registry.register_evidence(future)
    entry = AssuranceCrosswalkEntry(
        entry_id="future-entry",
        institution_id="bank-demo",
        scope_digest=scope.evidence_digest,
        framework=AssuranceFramework.FEDERAL_RESERVE_SR_26_2,
        framework_version="SR 26-2",
        reference_id="inventory_governance",
        applicability_assertion_digest=assertions[0].evidence_digest,
        coverage=EvidenceCoverage.SUPPORTED,
        evidence_reference_digests=(future.evidence_digest,),
        mapping_rationale="x",
        mapped_by_id="human",
        mapped_at=199,
    )
    with pytest.raises(GovernanceError, match="registered in the future"):
        registry.register_entry(entry)


def test_historical_package_verifies_after_profile_drift_but_is_not_current() -> None:
    registry, sr, _, scope, *_ = fixture()
    package = registry.build_evidence_package(
        scope,
        package_id="pkg-history",
        assembled_by_id="owner",
        assembled_at=130,
    )
    registry.register_package(package)
    sr_v2 = replace(sr, profile_version=2, source_document_digest=D6, registered_at=200)
    registry.register_mapping_profile(sr_v2)
    assert registry.register_mapping_profile(sr) == sr.evidence_digest
    registry.verify_package(package)
    assert registry.register_package(package) == package.evidence_digest
    with pytest.raises(GovernanceError, match="mapping profile is stale"):
        registry.assert_package_current(package)


def test_new_scope_cannot_bind_stale_mapping_profile() -> None:
    registry, sr, eu, scope, *_ = fixture()
    sr_v2 = replace(sr, profile_version=2, source_document_digest=D6, registered_at=200)
    registry.register_mapping_profile(sr_v2)
    stale_scope = replace(scope, scope_version=2, subject_artifact_digest=D5, recorded_at=210)
    with pytest.raises(GovernanceError, match="mapping profile is stale"):
        registry.register_scope(stale_scope)


def test_runtime_artifacts_match_strict_assurance_schemas() -> None:
    registry, sr, eu, scope, assertions, evidence, entries = fixture()
    package = registry.build_evidence_package(scope, package_id="pkg-schema", assembled_by_id="owner", assembled_at=130)
    root = Path(__file__).resolve().parents[1]
    cases = (
        ("assurance-mapping-profile.schema.json", sr),
        ("assurance-scope.schema.json", scope),
        ("assurance-applicability-assertion.schema.json", assertions[0]),
        ("assurance-evidence-reference.schema.json", evidence[0]),
        ("assurance-crosswalk-entry.schema.json", entries[0]),
        ("assurance-evidence-package.schema.json", package),
    )
    for filename, artifact in cases:
        schema = json.loads((root / "schemas" / filename).read_text(encoding="utf-8"))
        assert schema["additionalProperties"] is False
        jsonschema.Draft202012Validator(schema).validate(json.loads(canonical_json(artifact)))
