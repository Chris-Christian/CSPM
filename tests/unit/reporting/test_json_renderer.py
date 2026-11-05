import json

from cspm.models.enums import ScanStatus, Severity
from cspm.reporting.json_renderer import render_json_report


def test_json_report_contains_scan_inventory_all_severities_and_finding_fields(
    report_data_factory,
):
    data = report_data_factory(
        severities=(Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.LOW),
        evidence={"policy": {"Principal": "*", "labels": ["雪", 3]}},
    )

    result = json.loads(render_json_report(data))

    assert result["read_only"] is True
    assert result["scan"] == {
        "scan_id": str(data.scan.scan_id),
        "target": "localstack",
        "region": "us-east-1",
        "status": "completed",
        "started_at": "2026-11-05T09:00:00+00:00",
        "completed_at": "2026-11-05T10:00:00+00:00",
    }
    assert result["report_generated_at"] == "2026-11-05T12:30:00+00:00"
    assert result["inventory"] == {
        "total_resources": 4,
        "resource_counts_by_type": {"s3_bucket": 4},
    }
    assessment = result["assessment"]
    assert assessment["has_run"] is False
    assert assessment["completed_without_errors"] is False
    assert assessment["total_findings"] == 4
    assert assessment["severity_counts"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 1,
    }
    finding = result["findings"][0]
    assert {
        "finding_id",
        "fingerprint",
        "scan_id",
        "rule_id",
        "resource_id",
        "resource_type",
        "title",
        "severity",
        "cis_control",
        "remediation",
        "evidence",
        "detected_at",
    } <= finding.keys()
    assert finding["evidence"] == {"policy": {"Principal": "*", "labels": ["雪", 3]}}
    assert finding["resource_type"] == "s3_bucket"


def test_json_distinguishes_not_run_clean_and_errors_with_findings(report_data_factory):
    not_run = json.loads(render_json_report(report_data_factory()))["assessment"]
    clean = json.loads(render_json_report(report_data_factory(errors=())))["assessment"]
    incomplete = json.loads(render_json_report(report_data_factory(errors=...)))[
        "assessment"
    ]

    assert not_run["has_run"] is False and not_run["errors"] is None
    assert clean["has_run"] is True and clean["errors"] == []
    assert clean["completed_without_errors"] is True
    assert incomplete["has_run"] is True
    assert incomplete["completed_without_errors"] is False
    assert incomplete["errors"][0]["error_code"] == "IncompleteEvidence"
    assert incomplete["total_findings"] == 1


def test_json_empty_findings_with_errors_and_failed_or_running_scans(
    report_data_factory,
):
    failed = json.loads(
        render_json_report(
            report_data_factory(severities=(), errors=..., status=ScanStatus.FAILED)
        )
    )
    running = json.loads(
        render_json_report(
            report_data_factory(severities=(), errors=None, status=ScanStatus.RUNNING)
        )
    )

    assert failed["assessment"]["total_findings"] == 0
    assert len(failed["assessment"]["errors"]) == 1
    assert failed["scan"]["status"] == "failed"
    assert failed["scan"]["completed_at"] is not None
    assert running["scan"]["status"] == "running"
    assert running["scan"]["completed_at"] is None


def test_json_rendering_is_deterministic_for_fixed_report_data(report_data_factory):
    data = report_data_factory()

    assert render_json_report(data) == render_json_report(data)
