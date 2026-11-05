from cspm.models.enums import ScanStatus, Severity
from cspm.reporting.markdown_renderer import render_markdown_report


def test_markdown_contains_metadata_summary_grouping_evidence_and_remediation(
    report_data_factory,
):
    data = report_data_factory(
        severities=(Severity.CRITICAL, Severity.MEDIUM),
        evidence={"unicode": "雪☃", "multiline": "first\nsecond", "special": "` * |"},
        remediation="Apply the policy.\nReview access.",
    )

    result = render_markdown_report(data)

    assert "# CSPM Security Assessment Report" in result
    assert "## Scan metadata" in result
    assert "## Resource summary" in result
    assert "## Assessment summary" in result
    assert "## Findings by severity" in result
    assert "### CRITICAL (1)" in result
    assert "### HIGH (0)" in result
    assert "### MEDIUM (1)" in result
    assert "### LOW (0)" in result
    assert "READ-ONLY" in result
    assert "2026-11-05T12:30:00+00:00" in result
    assert "CIS control" in result
    assert "雪" in result
    assert "first\\nsecond" in result
    assert "Apply the policy.<br>Review access." in result
    assert "s3\\_bucket" in result


def test_markdown_omits_absent_cis_and_identifies_unrun_assessment(report_data_factory):
    data = report_data_factory(cis_control=None, errors=None)

    result = render_markdown_report(data)

    assert "CIS control" not in result
    assert "Assessment not run" in result
    assert "compliant" not in result.casefold()
    assert "is secure" not in result.casefold()


def test_markdown_reports_empty_findings_with_errors_without_clean_claim(
    report_data_factory,
):
    data = report_data_factory(severities=(), errors=..., status=ScanStatus.FAILED)

    result = render_markdown_report(data)

    assert "Total findings: **0**" in result
    assert "Incomplete assessment" in result
    assert "Some evidence could not be evaluated." in result
    assert "failed" in result
    assert "compliant" not in result.casefold()
    assert "is secure" not in result.casefold()


def test_markdown_running_scan_does_not_claim_successful_completion(
    report_data_factory,
):
    result = render_markdown_report(
        report_data_factory(errors=(), status=ScanStatus.RUNNING)
    )

    assert "scan lifecycle status is **running**" in result
    assert "makes no compliance claim" in result
