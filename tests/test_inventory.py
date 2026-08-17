import pytest

from modelriskops import (
    DependencyKind,
    DependencyRef,
    GovernanceError,
    InventoryRegistry,
    LifecycleState,
    ModelRecord,
    ModelType,
    ModelVersion,
    canonical_json,
    transition_model,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def model_record(model_id: str = "credit-risk") -> ModelRecord:
    return ModelRecord(
        institution_id="bank-a",
        model_id=model_id,
        name="Credit Risk Model",
        owner_id="risk-owner-17",
        business_use="Credit underwriting decision support",
        model_type=ModelType.MACHINE_LEARNING,
        lifecycle_state=LifecycleState.PROPOSED,
        deployment_context="Internal underwriting service",
        intended_users=("credit-risk-team",),
        prohibited_uses=("fully-autonomous-decline",),
    )


def model_version(version_id: str = "2026.08.1", artifact_digest: str = D1) -> ModelVersion:
    return ModelVersion(
        institution_id="bank-a",
        model_id="credit-risk",
        version_id=version_id,
        artifact_digest=artifact_digest,
        code_digest=D2,
        data_digest=D3,
        config_digest=D4,
        provenance_source="institution-model-registry",
        dependencies=(
            DependencyRef(
                kind=DependencyKind.DATASET,
                identifier="underwriting-features",
                version="2026-08-01",
                digest=D5,
            ),
        ),
    )


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_model_registration_is_idempotent_but_not_mutable() -> None:
    registry = InventoryRegistry()
    original = model_record()
    first_digest = registry.register_model(original)
    assert registry.register_model(original) == first_digest

    changed = ModelRecord(
        institution_id=original.institution_id,
        model_id=original.model_id,
        name=original.name,
        owner_id="different-owner",
        business_use=original.business_use,
        model_type=original.model_type,
        lifecycle_state=original.lifecycle_state,
        deployment_context=original.deployment_context,
        intended_users=original.intended_users,
        prohibited_uses=original.prohibited_uses,
    )
    with pytest.raises(GovernanceError, match="different governance content"):
        registry.register_model(changed)


def test_version_requires_registered_model() -> None:
    registry = InventoryRegistry()
    with pytest.raises(GovernanceError, match="before its model record"):
        registry.register_version(model_version())


def test_version_id_cannot_be_reused_with_different_provenance() -> None:
    registry = InventoryRegistry()
    registry.register_model(model_record())
    version = model_version()
    registry.register_version(version)

    changed = model_version(artifact_digest="a" * 64)
    with pytest.raises(GovernanceError, match="different provenance"):
        registry.register_version(changed)


def test_exact_version_digest_changes_when_artifact_changes() -> None:
    assert model_version().evidence_digest != model_version(artifact_digest="a" * 64).evidence_digest


def test_duplicate_dependency_identity_fails_closed() -> None:
    dep = DependencyRef(
        kind=DependencyKind.SYSTEM,
        identifier="feature-store",
        version="1",
        digest=D1,
    )
    with pytest.raises(GovernanceError, match="must not repeat"):
        ModelVersion(
            institution_id="bank-a",
            model_id="credit-risk",
            version_id="dup-dep",
            artifact_digest=D1,
            code_digest=D2,
            data_digest=D3,
            config_digest=D4,
            provenance_source="registry",
            dependencies=(dep, dep),
        )


def test_invalid_digest_is_rejected() -> None:
    with pytest.raises(GovernanceError, match="SHA-256"):
        model_version(artifact_digest="NOT-A-DIGEST")


def test_lifecycle_transition_is_closed_and_explicit() -> None:
    proposed = model_record()
    development = transition_model(proposed, LifecycleState.DEVELOPMENT)
    assert development.lifecycle_state is LifecycleState.DEVELOPMENT

    with pytest.raises(GovernanceError, match="unsupported lifecycle transition"):
        transition_model(proposed, LifecycleState.DEPLOYED)


def test_retired_model_cannot_reenter_lifecycle() -> None:
    retired = ModelRecord(
        institution_id="bank-a",
        model_id="legacy-model",
        name="Legacy Model",
        owner_id="risk-owner-1",
        business_use="Historical reference",
        model_type=ModelType.STATISTICAL,
        lifecycle_state=LifecycleState.RETIRED,
        deployment_context="None",
    )
    with pytest.raises(GovernanceError, match="unsupported lifecycle transition"):
        transition_model(retired, LifecycleState.DEVELOPMENT)


def test_snapshot_digest_is_order_independent() -> None:
    left = InventoryRegistry()
    right = InventoryRegistry()

    records = (model_record("a"), model_record("b"))
    for record in records:
        left.register_model(record)
    for record in reversed(records):
        right.register_model(record)

    assert left.snapshot_digest() == right.snapshot_digest()
