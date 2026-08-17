from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .models import GovernanceError, ModelRecord, ModelVersion
from .risk import RiskDecision


class ValidationDomain(str, Enum):
    CONCEPTUAL_SOUNDNESS = "conceptual_soundness"
    DATA_SUITABILITY = "data_suitability"
    IMPLEMENTATION_VERIFICATION = "implementation_verification"
    PERFORMANCE = "performance"
    ROBUSTNESS = "robustness"
    EXPLAINABILITY = "explainability"
    FAIRNESS = "fairness"
    SECURITY = "security"
    MONITORING_READINESS = "monitoring_readiness"
    LIMITATIONS = "limitations"


class TestStatus(str, Enum):
    NOT_STARTED = "not_started"
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class ValidationConclusion(str, Enum):
    PASS = "pass"
    PASS_WITH_CONDITIONS = "pass_with_conditions"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class ValidationTest:
    test_id: str
    domain: ValidationDomain
    mandatory: bool
    status: TestStatus
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.test_id.strip():
            raise GovernanceError("test_id must be non-empty")
        if self.status in {TestStatus.PASS, TestStatus.FAIL} and self.evidence_digest is None:
            raise GovernanceError("completed validation tests require evidence_digest")
        if self.evidence_digest is not None and not _is_digest(self.evidence_digest):
            raise GovernanceError("validation test evidence_digest must be SHA-256")
        if self.mandatory and self.status is TestStatus.NOT_APPLICABLE:
            raise GovernanceError("mandatory validation test cannot be not_applicable")


@dataclass(frozen=True, slots=True)
class ValidationPlan:
    institution_id: str
    model_id: str
    version_id: str
    model_digest: str
    model_version_digest: str
    risk_decision_digest: str
    validator_id: str
    validator_role: str
    independent_from_owner: bool
    tests: tuple[ValidationTest, ...]

    def __post_init__(self) -> None:
        for name in ("institution_id", "model_id", "version_id", "validator_id", "validator_role"):
            if not getattr(self, name).strip():
                raise GovernanceError(f"{name} must be non-empty")
        for name in ("model_digest", "model_version_digest", "risk_decision_digest"):
            if not _is_digest(getattr(self, name)):
                raise GovernanceError(f"{name} must be SHA-256")
        ids = [test.test_id for test in self.tests]
        if len(ids) != len(set(ids)):
            raise GovernanceError("validation test_id values must be unique")
        if not self.tests:
            raise GovernanceError("validation plan must contain tests")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    finding_id: str
    test_id: str
    severity: FindingSeverity
    status: FindingStatus
    evidence_digest: str
    description: str
    remediation_digest: str | None = None
    closed_by_validator_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("finding_id", "test_id", "description"):
            if not getattr(self, name).strip():
                raise GovernanceError(f"{name} must be non-empty")
        if not _is_digest(self.evidence_digest):
            raise GovernanceError("finding evidence_digest must be SHA-256")
        if self.remediation_digest is not None and not _is_digest(self.remediation_digest):
            raise GovernanceError("remediation_digest must be SHA-256")
        if self.status is FindingStatus.CLOSED:
            if self.remediation_digest is None or not self.closed_by_validator_id:
                raise GovernanceError("closed findings require remediation evidence and validator closure")
        elif self.closed_by_validator_id is not None:
            raise GovernanceError("only closed findings may carry closed_by_validator_id")

    @property
    def evidence_digest_bound(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ValidationResolution:
    plan_digest: str
    conclusion: ValidationConclusion
    blocking_finding_ids: tuple[str, ...]
    open_finding_ids: tuple[str, ...]
    completed_test_ids: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        if not _is_digest(self.plan_digest):
            raise GovernanceError("plan_digest must be SHA-256")
        if not self.rationale.strip():
            raise GovernanceError("validation resolution rationale must be non-empty")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def build_validation_plan(
    record: ModelRecord,
    version: ModelVersion,
    risk_decision: RiskDecision,
    *,
    validator_id: str,
    validator_role: str,
    independent_from_owner: bool,
    tests: Iterable[ValidationTest],
) -> ValidationPlan:
    if record.institution_id != version.institution_id or record.model_id != version.model_id:
        raise GovernanceError("model record and version identity do not match")
    if risk_decision.institution_id != record.institution_id or risk_decision.model_id != record.model_id:
        raise GovernanceError("risk decision does not belong to model record")
    if risk_decision.version_id != version.version_id:
        raise GovernanceError("risk decision does not belong to model version")
    if risk_decision.model_digest != record.evidence_digest:
        raise GovernanceError("risk decision is stale for model record")
    if risk_decision.model_version_digest != version.evidence_digest:
        raise GovernanceError("risk decision is stale for model version")
    if "independent_validation" in risk_decision.requirements and not independent_from_owner:
        raise GovernanceError("risk decision requires independent validation")
    if independent_from_owner and validator_id == record.owner_id:
        raise GovernanceError("model owner cannot serve as independent validator")

    return ValidationPlan(
        institution_id=record.institution_id,
        model_id=record.model_id,
        version_id=version.version_id,
        model_digest=record.evidence_digest,
        model_version_digest=version.evidence_digest,
        risk_decision_digest=risk_decision.evidence_digest,
        validator_id=validator_id,
        validator_role=validator_role,
        independent_from_owner=independent_from_owner,
        tests=tuple(sorted(tests, key=lambda item: item.test_id)),
    )


def resolve_validation(
    plan: ValidationPlan,
    findings: Iterable[ValidationFinding],
) -> ValidationResolution:
    finding_list = tuple(sorted(findings, key=lambda item: item.finding_id))
    ids = [finding.finding_id for finding in finding_list]
    if len(ids) != len(set(ids)):
        raise GovernanceError("finding_id values must be unique")

    test_ids = {test.test_id for test in plan.tests}
    if any(finding.test_id not in test_ids for finding in finding_list):
        raise GovernanceError("finding references a test outside the validation plan")
    if any(
        finding.status is FindingStatus.CLOSED
        and finding.closed_by_validator_id != plan.validator_id
        for finding in finding_list
    ):
        raise GovernanceError("finding closure must be performed by the plan validator")

    incomplete_mandatory = [
        test.test_id
        for test in plan.tests
        if test.mandatory and test.status not in {TestStatus.PASS, TestStatus.FAIL}
    ]
    failed_mandatory = [
        test.test_id for test in plan.tests if test.mandatory and test.status is TestStatus.FAIL
    ]
    open_findings = [finding for finding in finding_list if finding.status is not FindingStatus.CLOSED]
    blocking = [
        finding
        for finding in open_findings
        if finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
    ]

    if incomplete_mandatory:
        conclusion = ValidationConclusion.INCOMPLETE
        rationale = "Mandatory validation tests remain incomplete."
    elif failed_mandatory or blocking:
        conclusion = ValidationConclusion.FAIL
        rationale = "Mandatory validation failure or blocking finding remains unresolved."
    elif open_findings:
        conclusion = ValidationConclusion.PASS_WITH_CONDITIONS
        rationale = "Validation completed with non-blocking open findings."
    else:
        conclusion = ValidationConclusion.PASS
        rationale = "All mandatory validation tests completed without unresolved findings."

    completed = tuple(
        test.test_id for test in plan.tests if test.status in {TestStatus.PASS, TestStatus.FAIL}
    )
    return ValidationResolution(
        plan_digest=plan.evidence_digest,
        conclusion=conclusion,
        blocking_finding_ids=tuple(item.finding_id for item in blocking),
        open_finding_ids=tuple(item.finding_id for item in open_findings),
        completed_test_ids=completed,
        rationale=rationale,
    )
