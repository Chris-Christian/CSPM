"""Validated, report-specific data assembled from existing CSPM models."""

from dataclasses import dataclass
from datetime import UTC, datetime

from cspm.models import Finding, Resource, Scan
from cspm.models.enums import CollectorStatus, Severity
from cspm.rules.engine import EvaluationRecord

SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


@dataclass(frozen=True)
class FindingReport:
    """A finding joined to its persisted resource for report presentation."""

    finding: Finding
    resource: Resource


@dataclass(frozen=True)
class ReportData:
    """A read-only snapshot containing all data used by report renderers."""

    scan: Scan
    resources: tuple[Resource, ...]
    findings: tuple[FindingReport, ...]
    assessment_errors: tuple[EvaluationRecord, ...] | None
    generated_at: datetime

    def __post_init__(self) -> None:
        """Validate cross-model identities and normalize the report timestamp."""
        if self.generated_at.utcoffset() is None:
            raise ValueError("report generation timestamp must be timezone-aware")
        object.__setattr__(self, "generated_at", self.generated_at.astimezone(UTC))
        resources_by_identity = {
            (resource.scan_id, resource.resource_id): resource
            for resource in self.resources
        }
        if any(resource.scan_id != self.scan.scan_id for resource in self.resources):
            raise ValueError("report resources must belong to the report scan")
        if any(
            item.finding.scan_id != self.scan.scan_id
            or item.resource.scan_id != self.scan.scan_id
            or resources_by_identity.get(
                (item.finding.scan_id, item.finding.resource_id)
            )
            != item.resource
            for item in self.findings
        ):
            raise ValueError("report findings must match their persisted resources")
        if self.assessment_errors is not None and any(
            (self.scan.scan_id, error.resource_id) not in resources_by_identity
            or (
                error.finding is not None
                and all(
                    report_finding.finding.finding_id != error.finding.finding_id
                    for report_finding in self.findings
                )
            )
            for error in self.assessment_errors
        ):
            raise ValueError("report assessment errors must match persisted scan data")

    @property
    def assessment_has_run(self) -> bool:
        """Whether an assessment outcome was persisted for this scan."""
        return self.assessment_errors is not None

    @property
    def assessment_completed_without_errors(self) -> bool:
        """Whether assessment ran and persisted no evaluation errors."""
        return self.assessment_errors == ()

    @property
    def collectors_complete(self) -> bool:
        "True if Collector coverage was recorded and every collector succeeded."
        results = self.scan.collector_results
        return bool(results) and all(
            result.status is CollectorStatus.SUCCESS for result in results
        )

    @property
    def resource_counts_by_type(self) -> dict[str, int]:
        """Return resource counts in stable resource-type order."""
        counts: dict[str, int] = {}
        for resource in self.resources:
            counts[resource.resource_type] = counts.get(resource.resource_type, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def severity_counts(self) -> dict[Severity, int]:
        """Return counts for every severity, including categories with no findings."""
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for item in self.findings:
            counts[item.finding.severity] += 1
        return counts

    @property
    def findings_by_severity(self) -> dict[Severity, tuple[FindingReport, ...]]:
        """Group findings in stable severity and resource order."""
        groups: dict[Severity, list[FindingReport]] = {
            severity: [] for severity in SEVERITY_ORDER
        }
        for item in self.findings:
            groups[item.finding.severity].append(item)
        return {
            severity: tuple(
                sorted(
                    groups[severity],
                    key=lambda item: (
                        item.finding.resource_id,
                        item.finding.rule_id,
                        str(item.finding.finding_id),
                    ),
                )
            )
            for severity in SEVERITY_ORDER
        }


def normalize_generated_at(value: datetime) -> datetime:
    """Require an aware generation time and normalize it to UTC."""
    if value.utcoffset() is None:
        raise ValueError("report generation timestamp must be timezone-aware")
    return value.astimezone(UTC)
