from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .canonical import sha256_digest
from .deployment import DeploymentReleaseManifest, ProductionDeploymentRegistry
from .models import GovernanceError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GovernanceError(f"{name} must be a positive integer timestamp")
    return value


def _semver(name: str, value: str) -> str:
    value = _text(name, value)
    if not _SEMVER.fullmatch(value):
        raise GovernanceError(f"{name} must be semantic version text")
    return value


def _sorted_unique_text(name: str, values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise GovernanceError(f"{name} must not be empty")
    normalized = tuple(_text(name, item) for item in values)
    if normalized != tuple(sorted(normalized)) or len(normalized) != len(set(normalized)):
        raise GovernanceError(f"{name} must be unique and canonically sorted")
    return normalized


class GovernanceBoundary(str, Enum):
    INVENTORY_RISK = "inventory_risk"
    VALIDATION_APPROVAL = "validation_approval"
    MONITORING_CHANGE = "monitoring_change"
    GENAI = "genai"
    PORTFOLIO_THIRD_PARTY = "portfolio_third_party"
    ASSURANCE = "assurance"
    TENANT_CRYPTO = "tenant_crypto"
    PRODUCTION_REFERENCE = "production_reference"


class SecurityReviewStatus(str, Enum):
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"


REQUIRED_SECURITY_REVIEW_ITEMS: tuple[str, ...] = (
    "approval-exception-and-revalidation",
    "assurance-non-claims",
    "genai-overlay-and-human-oversight",
    "independent-validation-and-findings",
    "inventory-version-and-provenance",
    "monitoring-and-change-control",
    "portfolio-and-third-party-risk",
    "production-reference-egress-and-worker",
    "release-provenance-and-upgrade",
    "risk-policy-determinism",
    "signing-and-key-revocation",
    "tenant-isolation-and-crypto-lifecycle",
)

REQUIRED_V1_NON_CLAIMS: tuple[str, ...] = (
    "not-automated-model-validation",
    "not-certification-or-conformity-assessment",
    "not-deployed-rls-proof",
    "not-hardware-custody-proof",
    "not-legal-advice-or-regulatory-determination",
    "not-live-deployment-or-model-execution",
    "not-model-safety-or-factuality-guarantee",
    "not-production-fitness-guarantee",
    "not-supervisory-acceptance-determination",
)


@dataclass(frozen=True, slots=True)
class StableCompatibilityPolicy:
    stable_since_version: str
    compatibility_series: str
    semver_required: bool
    breaking_change_requires_major: bool
    python_symbol_removal_requires_major: bool
    cli_command_removal_requires_major: bool
    json_schema_removal_requires_major: bool
    json_required_field_removal_requires_major: bool
    json_enum_value_removal_requires_major: bool
    unknown_json_fields_rejected: bool
    deprecation_min_minor_releases: int
    declared_at: int

    def __post_init__(self) -> None:
        if _semver("stable_since_version", self.stable_since_version) != "1.0.0":
            raise GovernanceError("v1 compatibility policy must start at 1.0.0")
        if _text("compatibility_series", self.compatibility_series) != "1.x":
            raise GovernanceError("v1 compatibility series must be 1.x")
        for name in (
            "semver_required",
            "breaking_change_requires_major",
            "python_symbol_removal_requires_major",
            "cli_command_removal_requires_major",
            "json_schema_removal_requires_major",
            "json_required_field_removal_requires_major",
            "json_enum_value_removal_requires_major",
            "unknown_json_fields_rejected",
        ):
            if getattr(self, name) is not True:
                raise GovernanceError(f"{name} must be true for the v1 stable contract")
        if isinstance(self.deprecation_min_minor_releases, bool) or not isinstance(self.deprecation_min_minor_releases, int):
            raise GovernanceError("deprecation_min_minor_releases must be an integer")
        if not 2 <= self.deprecation_min_minor_releases <= 12:
            raise GovernanceError("v1 deprecation window must be between 2 and 12 minor releases")
        _timestamp("declared_at", self.declared_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PublicSurfaceManifest:
    release_version: str
    compatibility_policy_digest: str
    python_api_symbols: tuple[str, ...]
    cli_commands: tuple[str, ...]
    json_schema_baseline_digest: str
    generated_at: int

    def __post_init__(self) -> None:
        if _semver("release_version", self.release_version) != "1.0.0":
            raise GovernanceError("v1 public surface manifest must target 1.0.0")
        _digest("compatibility_policy_digest", self.compatibility_policy_digest)
        object.__setattr__(self, "python_api_symbols", _sorted_unique_text("python_api_symbols", self.python_api_symbols))
        object.__setattr__(self, "cli_commands", _sorted_unique_text("cli_commands", self.cli_commands))
        _digest("json_schema_baseline_digest", self.json_schema_baseline_digest)
        _timestamp("generated_at", self.generated_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class SupportedUpgradePath:
    source_series: str
    target_version: str
    source_release_digest: str
    target_release_digest: str
    preflight_evidence_digest: str
    migration_evidence_digest: str
    post_upgrade_validation_digest: str
    rollback_evidence_digest: str
    backup_required: bool
    breaking_changes_declared: bool
    declared_at: int

    def __post_init__(self) -> None:
        if _text("source_series", self.source_series) != "0.8.x":
            raise GovernanceError("v1 supports only the declared 0.8.x source series")
        if _semver("target_version", self.target_version) != "1.0.0":
            raise GovernanceError("v1 supported upgrade target must be 1.0.0")
        for name in (
            "source_release_digest",
            "target_release_digest",
            "preflight_evidence_digest",
            "migration_evidence_digest",
            "post_upgrade_validation_digest",
            "rollback_evidence_digest",
        ):
            _digest(name, getattr(self, name))
        if self.source_release_digest == self.target_release_digest:
            raise GovernanceError("source and target release digests must be distinct")
        if self.backup_required is not True:
            raise GovernanceError("v1 upgrade path requires backup evidence")
        if self.breaking_changes_declared is not False:
            raise GovernanceError("0.8.x to 1.0.0 reference upgrade must not declare an intentional breaking migration")
        _timestamp("declared_at", self.declared_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class SecurityReviewItem:
    item_id: str
    status: SecurityReviewStatus
    evidence_digest: str
    reviewer_rationale_digest: str
    risk_acceptance_human_id: str | None = None
    risk_acceptance_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "item_id", _text("item_id", self.item_id))
        if not isinstance(self.status, SecurityReviewStatus):
            raise GovernanceError("security review item status must be governed")
        _digest("evidence_digest", self.evidence_digest)
        _digest("reviewer_rationale_digest", self.reviewer_rationale_digest)
        if self.status is SecurityReviewStatus.CLOSED:
            if self.risk_acceptance_human_id is not None or self.risk_acceptance_digest is not None:
                raise GovernanceError("closed review items must not carry risk-acceptance fields")
        else:
            object.__setattr__(self, "risk_acceptance_human_id", _text("risk_acceptance_human_id", self.risk_acceptance_human_id or ""))
            _digest("risk_acceptance_digest", self.risk_acceptance_digest or "")

    @property
    def evidence_record_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IndependentSecurityReviewChecklist:
    release_version: str
    reviewer_id: str
    reviewer_independence_confirmed: bool
    items: tuple[SecurityReviewItem, ...]
    reviewed_at: int

    def __post_init__(self) -> None:
        if _semver("release_version", self.release_version) != "1.0.0":
            raise GovernanceError("independent security review must target 1.0.0")
        object.__setattr__(self, "reviewer_id", _text("reviewer_id", self.reviewer_id))
        if self.reviewer_independence_confirmed is not True:
            raise GovernanceError("reviewer independence must be explicitly confirmed by the reviewer")
        if len(self.items) != len(REQUIRED_SECURITY_REVIEW_ITEMS):
            raise GovernanceError("independent security review must contain every required v1 item")
        ids = tuple(item.item_id for item in self.items)
        if ids != REQUIRED_SECURITY_REVIEW_ITEMS:
            raise GovernanceError("independent security review items must be the exact canonical v1 set and order")
        _timestamp("reviewed_at", self.reviewed_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ResponsibilityScope:
    release_version: str
    legal_advice_provided: bool
    regulatory_compliance_determined: bool
    certification_claimed: bool
    supervisory_acceptance_claimed: bool
    production_fitness_claimed: bool
    institution_legal_review_required: bool
    privacy_data_protection_review_required: bool
    model_risk_accountable_owner_required: bool
    production_iam_network_review_required: bool
    records_retention_review_required: bool
    non_claims: tuple[str, ...]
    declared_at: int

    def __post_init__(self) -> None:
        if _semver("release_version", self.release_version) != "1.0.0":
            raise GovernanceError("responsibility scope must target 1.0.0")
        for name in (
            "legal_advice_provided",
            "regulatory_compliance_determined",
            "certification_claimed",
            "supervisory_acceptance_claimed",
            "production_fitness_claimed",
        ):
            if getattr(self, name) is not False:
                raise GovernanceError(f"{name} must remain false")
        for name in (
            "institution_legal_review_required",
            "privacy_data_protection_review_required",
            "model_risk_accountable_owner_required",
            "production_iam_network_review_required",
            "records_retention_review_required",
        ):
            if getattr(self, name) is not True:
                raise GovernanceError(f"{name} must remain an institution-owned responsibility")
        if self.non_claims != REQUIRED_V1_NON_CLAIMS:
            raise GovernanceError("responsibility scope must retain the exact v1 non-claims")
        _timestamp("declared_at", self.declared_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class BoundaryEvidenceReference:
    boundary: GovernanceBoundary
    artifact_digest: str
    evidence_description_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, GovernanceBoundary):
            raise GovernanceError("boundary evidence must use a governed boundary")
        _digest("artifact_digest", self.artifact_digest)
        _digest("evidence_description_digest", self.evidence_description_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class StableReleaseBaseline:
    release_version: str
    compatibility_policy_digest: str
    public_surface_manifest_digest: str
    production_release_manifest_digest: str
    supported_upgrade_path_digest: str
    security_review_checklist_digest: str
    responsibility_scope_digest: str
    reproducible_checksum_manifest_digest: str
    provenance_attestation_digest: str
    boundary_evidence: tuple[BoundaryEvidenceReference, ...]
    assembled_at: int

    def __post_init__(self) -> None:
        if _semver("release_version", self.release_version) != "1.0.0":
            raise GovernanceError("stable release baseline must target 1.0.0")
        for name in (
            "compatibility_policy_digest",
            "public_surface_manifest_digest",
            "production_release_manifest_digest",
            "supported_upgrade_path_digest",
            "security_review_checklist_digest",
            "responsibility_scope_digest",
            "reproducible_checksum_manifest_digest",
            "provenance_attestation_digest",
        ):
            _digest(name, getattr(self, name))
        expected = tuple(GovernanceBoundary)
        actual = tuple(item.boundary for item in self.boundary_evidence)
        if actual != expected:
            raise GovernanceError("stable baseline must bind every governance boundary in canonical order")
        artifact_digests = tuple(item.artifact_digest for item in self.boundary_evidence)
        if len(artifact_digests) != len(set(artifact_digests)):
            raise GovernanceError("stable baseline boundary artifact digests must be unique")
        _timestamp("assembled_at", self.assembled_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class StableReleaseRegistry:
    """Offline v1 baseline registry. It records governance evidence and performs no deployment or model execution."""

    def __init__(self, *, production_registry: ProductionDeploymentRegistry) -> None:
        if not isinstance(production_registry, ProductionDeploymentRegistry):
            raise GovernanceError("stable release registry requires the production reference registry")
        self.production_registry = production_registry
        self._baselines: dict[str, StableReleaseBaseline] = {}

    def _assert_source_registered(self, source_release: DeploymentReleaseManifest) -> None:
        history = self.production_registry.release_history(source_release.institution_id, source_release.tenant_id)
        if not any(item.evidence_digest == source_release.evidence_digest for item in history):
            raise GovernanceError("v0.8 source release is not registered in production history")

    @staticmethod
    def _assert_chronology(
        *,
        source_release: DeploymentReleaseManifest,
        target_release: DeploymentReleaseManifest,
        compatibility_policy: StableCompatibilityPolicy,
        public_surface: PublicSurfaceManifest,
        upgrade_path: SupportedUpgradePath,
        security_review: IndependentSecurityReviewChecklist,
        responsibility_scope: ResponsibilityScope,
        baseline: StableReleaseBaseline,
    ) -> None:
        if target_release.released_at < source_release.released_at:
            raise GovernanceError("v1 target release cannot predate the v0.8 source release")
        if public_surface.generated_at < compatibility_policy.declared_at:
            raise GovernanceError("public surface manifest cannot predate compatibility policy")
        if upgrade_path.declared_at < target_release.released_at:
            raise GovernanceError("supported upgrade path cannot predate the exact v1 target release")
        if security_review.reviewed_at < target_release.released_at:
            raise GovernanceError("independent security review cannot predate the exact v1 target release")
        if responsibility_scope.declared_at < target_release.released_at:
            raise GovernanceError("responsibility scope cannot predate the exact v1 target release")
        latest = max(
            compatibility_policy.declared_at,
            public_surface.generated_at,
            upgrade_path.declared_at,
            security_review.reviewed_at,
            responsibility_scope.declared_at,
            target_release.released_at,
        )
        if baseline.assembled_at < latest:
            raise GovernanceError("stable baseline cannot predate bound readiness evidence")

    def register_baseline(
        self,
        *,
        source_release: DeploymentReleaseManifest,
        target_release: DeploymentReleaseManifest,
        compatibility_policy: StableCompatibilityPolicy,
        public_surface: PublicSurfaceManifest,
        upgrade_path: SupportedUpgradePath,
        security_review: IndependentSecurityReviewChecklist,
        responsibility_scope: ResponsibilityScope,
        baseline: StableReleaseBaseline,
    ) -> str:
        existing = self._baselines.get(baseline.release_version)
        if existing is not None:
            if existing.evidence_digest != baseline.evidence_digest:
                raise GovernanceError("stable release baseline already exists with different content")
            return existing.evidence_digest
        if source_release.release_version.split(".")[:2] != ["0", "8"]:
            raise GovernanceError("v1 stable baseline requires an exact 0.8.x source release")
        if target_release.release_version != "1.0.0":
            raise GovernanceError("v1 stable baseline requires an exact 1.0.0 target release")
        if source_release.institution_id != target_release.institution_id or source_release.tenant_id != target_release.tenant_id:
            raise GovernanceError("source and target releases must belong to the same institution and tenant")
        self._assert_source_registered(source_release)
        self.production_registry.assert_release_current(target_release)
        if public_surface.compatibility_policy_digest != compatibility_policy.evidence_digest:
            raise GovernanceError("public surface does not bind the exact compatibility policy")
        if upgrade_path.source_release_digest != source_release.evidence_digest:
            raise GovernanceError("supported upgrade path does not bind the exact v0.8 source release")
        if upgrade_path.target_release_digest != target_release.evidence_digest:
            raise GovernanceError("supported upgrade path does not bind the exact v1 target release")
        if baseline.compatibility_policy_digest != compatibility_policy.evidence_digest:
            raise GovernanceError("stable baseline compatibility policy digest mismatch")
        if baseline.public_surface_manifest_digest != public_surface.evidence_digest:
            raise GovernanceError("stable baseline public surface digest mismatch")
        if baseline.production_release_manifest_digest != target_release.evidence_digest:
            raise GovernanceError("stable baseline production release digest mismatch")
        if baseline.supported_upgrade_path_digest != upgrade_path.evidence_digest:
            raise GovernanceError("stable baseline supported upgrade digest mismatch")
        if baseline.security_review_checklist_digest != security_review.evidence_digest:
            raise GovernanceError("stable baseline independent security review digest mismatch")
        if baseline.responsibility_scope_digest != responsibility_scope.evidence_digest:
            raise GovernanceError("stable baseline responsibility scope digest mismatch")
        if baseline.provenance_attestation_digest != target_release.provenance_attestation_digest:
            raise GovernanceError("stable baseline provenance must bind the exact target release evidence")
        self._assert_chronology(
            source_release=source_release,
            target_release=target_release,
            compatibility_policy=compatibility_policy,
            public_surface=public_surface,
            upgrade_path=upgrade_path,
            security_review=security_review,
            responsibility_scope=responsibility_scope,
            baseline=baseline,
        )
        self._baselines[baseline.release_version] = baseline
        return baseline.evidence_digest

    def assert_baseline_current(
        self,
        *,
        baseline: StableReleaseBaseline,
        source_release: DeploymentReleaseManifest,
        target_release: DeploymentReleaseManifest,
        upgrade_path: SupportedUpgradePath,
    ) -> None:
        registered = self._baselines.get(baseline.release_version)
        if registered is None or registered.evidence_digest != baseline.evidence_digest:
            raise GovernanceError("stable release baseline is not registered")
        self._assert_source_registered(source_release)
        if upgrade_path.evidence_digest != baseline.supported_upgrade_path_digest:
            raise GovernanceError("currentness check requires the exact supported upgrade path")
        if upgrade_path.source_release_digest != source_release.evidence_digest:
            raise GovernanceError("currentness check source release substitution detected")
        if upgrade_path.target_release_digest != target_release.evidence_digest:
            raise GovernanceError("currentness check target release substitution detected")
        if baseline.production_release_manifest_digest != target_release.evidence_digest:
            raise GovernanceError("stable baseline target release substitution detected")
        self.production_registry.assert_release_current(target_release)
