"""Read-only report-data preparation through the ScanRepository interface."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from cspm.reporting.data import FindingReport, ReportData, normalize_generated_at
from cspm.reporting.exceptions import ReportDataError, ReportNotFoundError

if TYPE_CHECKING:
    from cspm.persistence import ScanRepository


def build_report_data(
    repository: ScanRepository,
    scan_id: UUID,
    *,
    generated_at: datetime | None = None,
) -> ReportData:
    """Load a consistent report snapshot using repository read methods only."""
    if not isinstance(scan_id, UUID):
        raise ReportDataError("scan_id must be a UUID")
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise ReportNotFoundError(f"scan {scan_id} was not found")

    resources = tuple(repository.get_resources(scan_id))
    findings = tuple(repository.get_findings(scan_id))
    assessment_errors = repository.get_assessment_errors(scan_id)
    resources_by_identity = {
        (resource.scan_id, resource.resource_id): resource for resource in resources
    }

    finding_reports = []
    for finding in findings:
        resource = resources_by_identity.get((finding.scan_id, finding.resource_id))
        if resource is None:
            raise ReportDataError(
                "finding references a resource absent from the persisted scan"
            )
        finding_reports.append(FindingReport(finding=finding, resource=resource))

    timestamp = generated_at if generated_at is not None else datetime.now(UTC)
    try:
        timestamp = normalize_generated_at(timestamp)
    except (AttributeError, TypeError, ValueError):
        raise ReportDataError(
            "report generation timestamp must be timezone-aware"
        ) from None

    return ReportData(
        scan=scan,
        resources=resources,
        findings=tuple(finding_reports),
        assessment_errors=assessment_errors,
        generated_at=timestamp,
    )
