from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .models import GovernanceError


class AssuranceFramework(str, Enum):
    FEDERAL_RESERVE_SR_26_2 = "federal_reserve_sr_26_2"
    NIST_AI_RMF = "nist_ai_rmf"
    NIST_AI_600_1 = "nist_ai_600_1"
    ISO_IEC_42001 = "iso_iec_42001"
    EU_AI_ACT = "eu_ai_act"


SUPPORTED_FRAMEWORK_VERSIONS: dict[AssuranceFramework, str] = {
    AssuranceFramework.FEDERAL_RESERVE_SR_26_2: "SR 26-2",
    AssuranceFramework.NIST_AI_RMF: "1.0",
    AssuranceFramework.NIST_AI_600_1: "600-1",
    AssuranceFramework.ISO_IEC_42001: "2023",
    AssuranceFramework.EU_AI_ACT: "2024/1689@2026-07-27",
}


class AssuranceSubjectKind(str, Enum):
    MODEL_VERSION = "model_version"
    GOVERNANCE_DOSSIER = "governance_dossier"
    GENAI_OVERLAY = "genai_overlay"
    PORTFOLIO_SNAPSHOT = "portfolio_snapshot"
    OTHER = "other"


class Applicability(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class EvidenceCoverage(str, Enum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


class EUAIActRole(str, Enum):
    PROVIDER = "provider"
    DEPLOYER = "deployer"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    PRODUCT_MANUFACTURER = "product_manufacturer"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _sorted_unique_text(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_text(name, value) for value in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must not be empty")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must be unique")
    ordered = tuple(sorted(cleaned))
    if ordered != cleaned:
        raise GovernanceError(f"{name} must be canonically sorted")
    return cleaned


def _sorted_unique_digests(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_digest(name, value) for value in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must not be empty")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must be unique")
    ordered = tuple(sorted(cleaned))
    if ordered != cleaned:
        raise GovernanceError(f"{name} must be canonically sorted")
    return cleaned


def _framework_version(framework: AssuranceFramework, version: str) -> str:
    if not isinstance(framework, AssuranceFramework):
        raise GovernanceError("assurance framework must be governed")
    expected = SUPPORTED_FRAMEWORK_VERSIONS[framework]
    if version != expected:
        raise GovernanceError(f"framework_version must be pinned to {expected} for {framework.value}")
    return version


@dataclass(frozen=True, slots=True)
class AssuranceMappingProfile:
    institution_id: str
    profile_id: str
    profile_version: int
    framework: AssuranceFramework
    framework_version: str
    reference_ids: tuple[str, ...]
    source_document_digest: str
    owner_id: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "profile_id", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("profile_version", self.profile_version)
        _framework_version(self.framework, self.framework_version)
        object.__setattr__(self, "reference_ids", _sorted_unique_text("reference_ids", self.reference_ids))
        _digest("source_document_digest", self.source_document_digest)
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AssuranceScope:
    institution_id: str
    scope_id: str
    scope_version: int
    subject_kind: AssuranceSubjectKind
    subject_id: str
    subject_version: str
    subject_artifact_digest: str
    context_digest: str
    owner_id: str
    mapping_profile_digests: tuple[str, ...]
    recorded_at: int

    def __post_init__(self) -> None:
        for name in ("institution_id", "scope_id", "subject_id", "subject_version", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("scope_version", self.scope_version)
        if not isinstance(self.subject_kind, AssuranceSubjectKind):
            raise GovernanceError("assurance subject kind must be governed")
        _digest("subject_artifact_digest", self.subject_artifact_digest)
        _digest("context_digest", self.context_digest)
        object.__setattr__(self, "mapping_profile_digests", _sorted_unique_digests("mapping_profile_digests", self.mapping_profile_digests))
        _timestamp("recorded_at", self.recorded_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AssuranceApplicabilityAssertion:
    assertion_id: str
    institution_id: str
    scope_digest: str
    framework: AssuranceFramework
    framework_version: str
    reference_id: str
    applicability: Applicability
    eu_ai_act_roles: tuple[EUAIActRole, ...]
    confirmation_basis: str
    confirmed_by_id: str
    confirmed_at: int

    def __post_init__(self) -> None:
        for name in ("assertion_id", "institution_id", "reference_id", "confirmation_basis", "confirmed_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("scope_digest", self.scope_digest)
        _framework_version(self.framework, self.framework_version)
        if not isinstance(self.applicability, Applicability):
            raise GovernanceError("applicability must be human-confirmed")
        if any(not isinstance(role, EUAIActRole) for role in self.eu_ai_act_roles):
            raise GovernanceError("eu_ai_act_roles must contain governed roles")
        if len(self.eu_ai_act_roles) != len(set(self.eu_ai_act_roles)):
            raise GovernanceError("eu_ai_act_roles must be unique")
        ordered_roles = tuple(sorted(self.eu_ai_act_roles, key=lambda role: role.value))
        if ordered_roles != self.eu_ai_act_roles:
            raise GovernanceError("eu_ai_act_roles must be canonically sorted")
        if self.framework is AssuranceFramework.EU_AI_ACT:
            if self.applicability is Applicability.APPLICABLE and not self.eu_ai_act_roles:
                raise GovernanceError("applicable EU AI Act assertion requires at least one human-confirmed operator role")
        elif self.eu_ai_act_roles:
            raise GovernanceError("EU AI Act roles are only valid for EU AI Act assertions")
        _timestamp("confirmed_at", self.confirmed_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AssuranceEvidenceReference:
    evidence_id: str
    institution_id: str
    scope_digest: str
    subject_artifact_digest: str
    artifact_type: str
    source_component: str
    evidence_basis: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("evidence_id", "institution_id", "artifact_type", "source_component", "evidence_basis"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("scope_digest", self.scope_digest)
        _digest("subject_artifact_digest", self.subject_artifact_digest)
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AssuranceCrosswalkEntry:
    entry_id: str
    institution_id: str
    scope_digest: str
    framework: AssuranceFramework
    framework_version: str
    reference_id: str
    applicability_assertion_digest: str
    coverage: EvidenceCoverage
    evidence_reference_digests: tuple[str, ...]
    mapping_rationale: str
    mapped_by_id: str
    mapped_at: int

    def __post_init__(self) -> None:
        for name in ("entry_id", "institution_id", "reference_id", "mapping_rationale", "mapped_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("scope_digest", self.scope_digest)
        _framework_version(self.framework, self.framework_version)
        _digest("applicability_assertion_digest", self.applicability_assertion_digest)
        if not isinstance(self.coverage, EvidenceCoverage):
            raise GovernanceError("assurance evidence coverage must be governed")
        object.__setattr__(self, "evidence_reference_digests", _sorted_unique_digests("evidence_reference_digests", self.evidence_reference_digests, allow_empty=True))
        if self.coverage in {EvidenceCoverage.SUPPORTED, EvidenceCoverage.PARTIAL}:
            if not self.evidence_reference_digests:
                raise GovernanceError("supported or partial coverage requires evidence references")
        elif self.evidence_reference_digests:
            raise GovernanceError("gap or not_applicable coverage must not carry evidence references")
        _timestamp("mapped_at", self.mapped_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class FrameworkCoverageSummary:
    framework: AssuranceFramework
    framework_version: str
    required_reference_count: int
    supported_count: int
    partial_count: int
    gap_count: int
    not_applicable_count: int

    def __post_init__(self) -> None:
        _framework_version(self.framework, self.framework_version)
        for name in ("required_reference_count", "supported_count", "partial_count", "gap_count", "not_applicable_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GovernanceError(f"{name} must be a non-negative integer")
        if self.required_reference_count <= 0:
            raise GovernanceError("required_reference_count must be positive")
        if self.supported_count + self.partial_count + self.gap_count + self.not_applicable_count != self.required_reference_count:
            raise GovernanceError("assurance coverage summary counts must equal required references")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AssuranceEvidencePackage:
    package_id: str
    institution_id: str
    scope_digest: str
    mapping_profile_digests: tuple[str, ...]
    applicability_assertion_digests: tuple[str, ...]
    evidence_reference_digests: tuple[str, ...]
    crosswalk_entry_digests: tuple[str, ...]
    coverage_summaries: tuple[FrameworkCoverageSummary, ...]
    assembled_by_id: str
    assembled_at: int
    certification_claimed: bool = False
    conformity_claimed: bool = False
    legal_compliance_determined: bool = False
    supervisory_acceptance_claimed: bool = False
    requires_human_review: bool = True

    def __post_init__(self) -> None:
        for name in ("package_id", "institution_id", "assembled_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("scope_digest", self.scope_digest)
        for name, values, allow_empty in (("mapping_profile_digests", self.mapping_profile_digests, False), ("applicability_assertion_digests", self.applicability_assertion_digests, False), ("evidence_reference_digests", self.evidence_reference_digests, True), ("crosswalk_entry_digests", self.crosswalk_entry_digests, False)):
            object.__setattr__(self, name, _sorted_unique_digests(name, values, allow_empty=allow_empty))
        if not self.coverage_summaries:
            raise GovernanceError("assurance package must include framework coverage summaries")
        if any(not isinstance(item, FrameworkCoverageSummary) for item in self.coverage_summaries):
            raise GovernanceError("coverage_summaries must contain FrameworkCoverageSummary values")
        ordered = tuple(sorted(self.coverage_summaries, key=lambda item: item.framework.value))
        if ordered != self.coverage_summaries:
            raise GovernanceError("coverage_summaries must be canonically sorted")
        frameworks = tuple(item.framework for item in self.coverage_summaries)
        if len(frameworks) != len(set(frameworks)):
            raise GovernanceError("coverage_summaries must contain at most one summary per framework")
        _timestamp("assembled_at", self.assembled_at)
        if self.certification_claimed is not False:
            raise GovernanceError("assurance packages cannot claim certification")
        if self.conformity_claimed is not False:
            raise GovernanceError("assurance packages cannot claim conformity")
        if self.legal_compliance_determined is not False:
            raise GovernanceError("assurance packages cannot determine legal compliance")
        if self.supervisory_acceptance_claimed is not False:
            raise GovernanceError("assurance packages cannot claim supervisory acceptance")
        if self.requires_human_review is not True:
            raise GovernanceError("assurance packages always require human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class AssuranceEvidenceRegistry:
    """Append-only assurance mapping registry; it never infers applicability or compliance."""

    def __init__(self) -> None:
        self._profiles: dict[tuple[str, str, int], AssuranceMappingProfile] = {}
        self._scopes: dict[tuple[str, str, int], AssuranceScope] = {}
        self._assertions: dict[tuple[str, str], AssuranceApplicabilityAssertion] = {}
        self._evidence: dict[tuple[str, str], AssuranceEvidenceReference] = {}
        self._entries: dict[tuple[str, str], AssuranceCrosswalkEntry] = {}
        self._packages: dict[tuple[str, str], AssuranceEvidencePackage] = {}

    @staticmethod
    def _same_or_conflict(existing, candidate, label: str) -> str:
        if existing.evidence_digest != candidate.evidence_digest:
            raise GovernanceError(f"{label} identity already exists with different content")
        return existing.evidence_digest

    def register_mapping_profile(self, profile: AssuranceMappingProfile) -> str:
        key = (profile.institution_id, profile.profile_id, profile.profile_version)
        existing = self._profiles.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, profile, "assurance mapping profile")
        history = [item for (institution_id, profile_id, _), item in self._profiles.items() if institution_id == profile.institution_id and profile_id == profile.profile_id]
        expected_version = 1 if not history else max(item.profile_version for item in history) + 1
        if profile.profile_version != expected_version:
            raise GovernanceError("assurance mapping profile versions must be contiguous")
        if history:
            latest = max(item.registered_at for item in history)
            if profile.registered_at < latest:
                raise GovernanceError("assurance mapping profile cannot backdate profile history")
            if any(item.framework is not profile.framework for item in history):
                raise GovernanceError("assurance mapping profile identity cannot change framework")
        self._profiles[key] = profile
        return profile.evidence_digest

    def _profile_by_digest(self, institution_id: str, digest: str) -> AssuranceMappingProfile:
        for (profile_institution, _, _), profile in self._profiles.items():
            if profile_institution == institution_id and profile.evidence_digest == digest:
                return profile
        raise GovernanceError("unknown assurance mapping profile digest")

    def current_mapping_profile(self, institution_id: str, profile_id: str) -> AssuranceMappingProfile:
        profiles = [item for (profile_institution, current_profile_id, _), item in self._profiles.items() if profile_institution == institution_id and current_profile_id == profile_id]
        if not profiles:
            raise GovernanceError("unknown assurance mapping profile")
        return max(profiles, key=lambda item: item.profile_version)

    def assert_mapping_profile_current(self, profile: AssuranceMappingProfile) -> None:
        current = self.current_mapping_profile(profile.institution_id, profile.profile_id)
        if current.evidence_digest != profile.evidence_digest:
            raise GovernanceError("assurance mapping profile is stale")

    def register_scope(self, scope: AssuranceScope) -> str:
        key = (scope.institution_id, scope.scope_id, scope.scope_version)
        existing = self._scopes.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, scope, "assurance scope")
        history = [item for (institution_id, scope_id, _), item in self._scopes.items() if institution_id == scope.institution_id and scope_id == scope.scope_id]
        expected_version = 1 if not history else max(item.scope_version for item in history) + 1
        if scope.scope_version != expected_version:
            raise GovernanceError("assurance scope versions must be contiguous")
        if history and scope.recorded_at < max(item.recorded_at for item in history):
            raise GovernanceError("assurance scope cannot backdate scope history")
        profiles = tuple(self._profile_by_digest(scope.institution_id, digest) for digest in scope.mapping_profile_digests)
        frameworks = tuple(profile.framework for profile in profiles)
        if len(frameworks) != len(set(frameworks)):
            raise GovernanceError("assurance scope must bind at most one mapping profile per framework")
        for profile in profiles:
            self.assert_mapping_profile_current(profile)
            if profile.registered_at > scope.recorded_at:
                raise GovernanceError("assurance scope cannot predate a bound mapping profile")
        self._scopes[key] = scope
        return scope.evidence_digest

    def _scope_by_digest(self, institution_id: str, digest: str) -> AssuranceScope:
        for (scope_institution, _, _), scope in self._scopes.items():
            if scope_institution == institution_id and scope.evidence_digest == digest:
                return scope
        raise GovernanceError("unknown assurance scope digest")

    def current_scope(self, institution_id: str, scope_id: str) -> AssuranceScope:
        scopes = [item for (scope_institution, current_scope_id, _), item in self._scopes.items() if scope_institution == institution_id and current_scope_id == scope_id]
        if not scopes:
            raise GovernanceError("unknown assurance scope")
        return max(scopes, key=lambda item: item.scope_version)

    def assert_scope_current(self, scope: AssuranceScope) -> None:
        current = self.current_scope(scope.institution_id, scope.scope_id)
        if current.evidence_digest != scope.evidence_digest:
            raise GovernanceError("assurance scope is stale")
        for digest in scope.mapping_profile_digests:
            self.assert_mapping_profile_current(self._profile_by_digest(scope.institution_id, digest))

    def _required_reference_profile(self, scope: AssuranceScope, framework: AssuranceFramework, framework_version: str, reference_id: str) -> AssuranceMappingProfile:
        _framework_version(framework, framework_version)
        matches = []
        for digest in scope.mapping_profile_digests:
            profile = self._profile_by_digest(scope.institution_id, digest)
            if profile.framework is framework and profile.framework_version == framework_version and reference_id in profile.reference_ids:
                matches.append(profile)
        if len(matches) != 1:
            raise GovernanceError("assurance reference is not required by the exact scope mapping profile")
        return matches[0]

    def register_applicability(self, assertion: AssuranceApplicabilityAssertion) -> str:
        scope = self._scope_by_digest(assertion.institution_id, assertion.scope_digest)
        self._required_reference_profile(scope, assertion.framework, assertion.framework_version, assertion.reference_id)
        if assertion.confirmed_at < scope.recorded_at:
            raise GovernanceError("applicability confirmation cannot predate assurance scope")
        key = (assertion.institution_id, assertion.assertion_id)
        existing = self._assertions.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, assertion, "assurance applicability assertion")
        conflict = [item for (institution_id, _), item in self._assertions.items() if institution_id == assertion.institution_id and item.scope_digest == assertion.scope_digest and item.framework is assertion.framework and item.framework_version == assertion.framework_version and item.reference_id == assertion.reference_id]
        if conflict:
            raise GovernanceError("exact assurance scope/framework reference already has an applicability assertion")
        self._assertions[key] = assertion
        return assertion.evidence_digest

    def _assertion_by_digest(self, institution_id: str, digest: str) -> AssuranceApplicabilityAssertion:
        for (assertion_institution, _), assertion in self._assertions.items():
            if assertion_institution == institution_id and assertion.evidence_digest == digest:
                return assertion
        raise GovernanceError("unknown assurance applicability assertion digest")

    def register_evidence(self, evidence: AssuranceEvidenceReference) -> str:
        scope = self._scope_by_digest(evidence.institution_id, evidence.scope_digest)
        if evidence.registered_at < scope.recorded_at:
            raise GovernanceError("assurance evidence registration cannot predate assurance scope")
        key = (evidence.institution_id, evidence.evidence_id)
        existing = self._evidence.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, evidence, "assurance evidence reference")
        self._evidence[key] = evidence
        return evidence.evidence_digest

    def _evidence_by_digest(self, institution_id: str, digest: str) -> AssuranceEvidenceReference:
        for (evidence_institution, _), evidence in self._evidence.items():
            if evidence_institution == institution_id and evidence.evidence_digest == digest:
                return evidence
        raise GovernanceError("unknown assurance evidence reference digest")

    def register_entry(self, entry: AssuranceCrosswalkEntry) -> str:
        scope = self._scope_by_digest(entry.institution_id, entry.scope_digest)
        self._required_reference_profile(scope, entry.framework, entry.framework_version, entry.reference_id)
        assertion = self._assertion_by_digest(entry.institution_id, entry.applicability_assertion_digest)
        if assertion.scope_digest != entry.scope_digest or assertion.framework is not entry.framework or assertion.framework_version != entry.framework_version or assertion.reference_id != entry.reference_id:
            raise GovernanceError("assurance crosswalk entry does not match the exact applicability assertion")
        if entry.mapped_at < assertion.confirmed_at:
            raise GovernanceError("assurance mapping cannot predate applicability confirmation")
        if assertion.applicability is Applicability.NOT_APPLICABLE:
            if entry.coverage is not EvidenceCoverage.NOT_APPLICABLE:
                raise GovernanceError("not-applicable assertion requires not_applicable coverage")
        elif entry.coverage is EvidenceCoverage.NOT_APPLICABLE:
            raise GovernanceError("applicable assertion cannot be mapped as not_applicable")
        for digest in entry.evidence_reference_digests:
            evidence = self._evidence_by_digest(entry.institution_id, digest)
            if evidence.scope_digest != entry.scope_digest:
                raise GovernanceError("assurance crosswalk evidence belongs to a different scope")
            if evidence.registered_at > entry.mapped_at:
                raise GovernanceError("assurance mapping cannot use evidence registered in the future")
        key = (entry.institution_id, entry.entry_id)
        existing = self._entries.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, entry, "assurance crosswalk entry")
        conflict = [item for (institution_id, _), item in self._entries.items() if institution_id == entry.institution_id and item.scope_digest == entry.scope_digest and item.framework is entry.framework and item.framework_version == entry.framework_version and item.reference_id == entry.reference_id]
        if conflict:
            raise GovernanceError("exact assurance scope/framework reference already has a crosswalk entry")
        self._entries[key] = entry
        return entry.evidence_digest

    def _scope_profiles(self, scope: AssuranceScope) -> tuple[AssuranceMappingProfile, ...]:
        return tuple(sorted((self._profile_by_digest(scope.institution_id, digest) for digest in scope.mapping_profile_digests), key=lambda item: item.framework.value))

    def _scope_assertions(self, scope: AssuranceScope) -> tuple[AssuranceApplicabilityAssertion, ...]:
        return tuple(sorted((item for (institution_id, _), item in self._assertions.items() if institution_id == scope.institution_id and item.scope_digest == scope.evidence_digest), key=lambda item: (item.framework.value, item.reference_id)))

    def _scope_entries(self, scope: AssuranceScope) -> tuple[AssuranceCrosswalkEntry, ...]:
        return tuple(sorted((item for (institution_id, _), item in self._entries.items() if institution_id == scope.institution_id and item.scope_digest == scope.evidence_digest), key=lambda item: (item.framework.value, item.reference_id)))

    def _scope_evidence(self, scope: AssuranceScope) -> tuple[AssuranceEvidenceReference, ...]:
        return tuple(sorted((item for (institution_id, _), item in self._evidence.items() if institution_id == scope.institution_id and item.scope_digest == scope.evidence_digest), key=lambda item: item.evidence_id))

    def _coverage_summaries(self, profiles: tuple[AssuranceMappingProfile, ...], entries: tuple[AssuranceCrosswalkEntry, ...]) -> tuple[FrameworkCoverageSummary, ...]:
        summaries = []
        for profile in profiles:
            framework_entries = tuple(item for item in entries if item.framework is profile.framework and item.framework_version == profile.framework_version)
            summaries.append(FrameworkCoverageSummary(framework=profile.framework, framework_version=profile.framework_version, required_reference_count=len(profile.reference_ids), supported_count=sum(item.coverage is EvidenceCoverage.SUPPORTED for item in framework_entries), partial_count=sum(item.coverage is EvidenceCoverage.PARTIAL for item in framework_entries), gap_count=sum(item.coverage is EvidenceCoverage.GAP for item in framework_entries), not_applicable_count=sum(item.coverage is EvidenceCoverage.NOT_APPLICABLE for item in framework_entries)))
        return tuple(sorted(summaries, key=lambda item: item.framework.value))

    def build_evidence_package(self, scope: AssuranceScope, *, package_id: str, assembled_by_id: str, assembled_at: int) -> AssuranceEvidencePackage:
        registered = self._scope_by_digest(scope.institution_id, scope.evidence_digest)
        if registered.evidence_digest != scope.evidence_digest:
            raise GovernanceError("assurance scope is not the exact registered artifact")
        self.assert_scope_current(scope)
        if assembled_at < scope.recorded_at:
            raise GovernanceError("assurance package cannot predate assurance scope")
        profiles = self._scope_profiles(scope)
        assertions = self._scope_assertions(scope)
        entries = self._scope_entries(scope)
        all_evidence = self._scope_evidence(scope)
        required = {(profile.framework, profile.framework_version, reference_id) for profile in profiles for reference_id in profile.reference_ids}
        assertion_keys = {(item.framework, item.framework_version, item.reference_id) for item in assertions}
        entry_keys = {(item.framework, item.framework_version, item.reference_id) for item in entries}
        if assertion_keys != required:
            raise GovernanceError("assurance package requires exactly one applicability assertion for every required reference")
        if entry_keys != required:
            raise GovernanceError("assurance package requires exactly one crosswalk entry for every required reference")
        used_evidence_digests = tuple(sorted({digest for entry in entries for digest in entry.evidence_reference_digests}))
        registered_evidence_by_digest = {item.evidence_digest: item for item in all_evidence}
        if any(digest not in registered_evidence_by_digest for digest in used_evidence_digests):
            raise GovernanceError("assurance package references unknown scope evidence")
        latest_component_time = max([scope.recorded_at] + [profile.registered_at for profile in profiles] + [assertion.confirmed_at for assertion in assertions] + [entry.mapped_at for entry in entries] + [registered_evidence_by_digest[digest].registered_at for digest in used_evidence_digests])
        if assembled_at < latest_component_time:
            raise GovernanceError("assurance package cannot predate included governance evidence")
        return AssuranceEvidencePackage(package_id=package_id, institution_id=scope.institution_id, scope_digest=scope.evidence_digest, mapping_profile_digests=tuple(sorted(profile.evidence_digest for profile in profiles)), applicability_assertion_digests=tuple(sorted(item.evidence_digest for item in assertions)), evidence_reference_digests=used_evidence_digests, crosswalk_entry_digests=tuple(sorted(item.evidence_digest for item in entries)), coverage_summaries=self._coverage_summaries(profiles, entries), assembled_by_id=assembled_by_id, assembled_at=assembled_at)

    def register_package(self, package: AssuranceEvidencePackage) -> str:
        key = (package.institution_id, package.package_id)
        existing = self._packages.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, package, "assurance evidence package")
        scope = self._scope_by_digest(package.institution_id, package.scope_digest)
        expected = self.build_evidence_package(scope, package_id=package.package_id, assembled_by_id=package.assembled_by_id, assembled_at=package.assembled_at)
        if expected.evidence_digest != package.evidence_digest:
            raise GovernanceError("assurance evidence package does not reproduce from registered evidence")
        self._packages[key] = package
        return package.evidence_digest

    def verify_package(self, package: AssuranceEvidencePackage) -> None:
        registered = self._packages.get((package.institution_id, package.package_id))
        if registered is None or registered.evidence_digest != package.evidence_digest:
            raise GovernanceError("assurance evidence package is not the exact registered artifact")
        scope = self._scope_by_digest(package.institution_id, package.scope_digest)
        profiles = self._scope_profiles(scope)
        assertions = self._scope_assertions(scope)
        entries = self._scope_entries(scope)
        used_evidence = tuple(sorted({digest for entry in entries for digest in entry.evidence_reference_digests}))
        expected = AssuranceEvidencePackage(package_id=package.package_id, institution_id=scope.institution_id, scope_digest=scope.evidence_digest, mapping_profile_digests=tuple(sorted(item.evidence_digest for item in profiles)), applicability_assertion_digests=tuple(sorted(item.evidence_digest for item in assertions)), evidence_reference_digests=used_evidence, crosswalk_entry_digests=tuple(sorted(item.evidence_digest for item in entries)), coverage_summaries=self._coverage_summaries(profiles, entries), assembled_by_id=package.assembled_by_id, assembled_at=package.assembled_at)
        if expected.evidence_digest != package.evidence_digest:
            raise GovernanceError("assurance evidence package does not reproduce from historical registered evidence")

    def assert_package_current(self, package: AssuranceEvidencePackage) -> None:
        self.verify_package(package)
        scope = self._scope_by_digest(package.institution_id, package.scope_digest)
        self.assert_scope_current(scope)
