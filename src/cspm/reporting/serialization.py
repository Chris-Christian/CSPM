"""Shared deterministic conversion of report data to JSON-compatible values."""

from typing import Any

from cspm.reporting.data import SEVERITY_ORDER, ReportData


def report_document(data: ReportData) -> dict[str, Any]:
    """Build the shared report document without flattening evidence values."""
    scan = data.scan
    return {
        "report_generated_at": data.generated_at.isoformat(),
        "read_only": True,
        "scan": {
            "scan_id": str(scan.scan_id),
            "target": scan.target.value,
            "region": scan.region,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat(),
            "completed_at": (
                scan.completed_at.isoformat() if scan.completed_at is not None else None
            ),
        },
        "inventory": {
            "total_resources": len(data.resources),
            "resource_counts_by_type": data.resource_counts_by_type,
        },
        "assessment": {
            "has_run": data.assessment_has_run,
            "completed_without_errors": data.assessment_completed_without_errors,
            "total_findings": len(data.findings),
            "severity_counts": {
                severity.value: data.severity_counts[severity]
                for severity in SEVERITY_ORDER
            },
            "errors": (
                None
                if data.assessment_errors is None
                else [
                    {
                        "resource_id": item.resource_id,
                        "resource_type": item.resource_type,
                        "rule_id": item.rule_id,
                        "error_code": item.error_code,
                        "message": item.message,
                        "error_codes": list(item.error_codes),
                        "finding_id": (
                            str(item.finding.finding_id)
                            if item.finding is not None
                            else None
                        ),
                    }
                    for item in data.assessment_errors
                ]
            ),
        },
        "findings": [
            {
                "finding_id": str(item.finding.finding_id),
                "fingerprint": item.finding.fingerprint,
                "scan_id": str(item.finding.scan_id),
                "rule_id": item.finding.rule_id,
                "resource_id": item.finding.resource_id,
                "resource_type": item.resource.resource_type,
                "title": item.finding.title,
                "severity": item.finding.severity.value,
                "cis_control": item.finding.cis_control,
                "remediation": item.finding.remediation,
                "evidence": item.finding.evidence,
                "detected_at": item.finding.detected_at.isoformat(),
            }
            for item in sorted(
                data.findings,
                key=lambda entry: (
                    entry.finding.severity.value,
                    entry.finding.resource_id,
                    entry.finding.rule_id,
                    str(entry.finding.finding_id),
                ),
            )
        ],
    }
