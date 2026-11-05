from cspm.models.enums import ScanStatus, Severity
from cspm.reporting.html_renderer import render_html_report


def test_html_contains_report_sections_severity_groups_and_optional_cis(
    report_data_factory,
):
    data = report_data_factory(
        severities=(Severity.CRITICAL, Severity.LOW),
        cis_control=None,
    )

    result = render_html_report(data)

    assert "CSPM Security Assessment Report" in result
    assert str(data.scan.scan_id) in result
    assert "localstack" in result
    assert "Resources discovered" in result
    assert "Severity summary" in result
    assert "CRITICAL</strong><br>1 finding(s)" in result
    assert "HIGH</strong><br>0 finding(s)" in result
    assert "LOW (1)" in result
    assert "Findings by severity" in result
    assert "Collected resource metadata and tags" in result
    assert "READ-ONLY" in result
    assert "CIS control" not in result


def test_html_autoescapes_all_untrusted_report_values(report_data_factory):
    malicious = '<script>alert("stored data")</script>'
    data = report_data_factory(
        metadata={"attacker-key": malicious},
        tags={"attacker-key": malicious},
        evidence={"attacker": malicious},
        title=malicious,
        remediation=malicious,
    )

    result = render_html_report(data)

    assert "<script" not in result.casefold()
    assert "</script>" not in result.casefold()
    assert "&lt;script&gt;" in result
    assert "&lt;/script&gt;" in result
    assert "alert(&#34;stored data&#34;)" in result
    assert "<script src=" not in result.casefold()
    assert "<link" not in result.casefold()
    assert "http://" not in result.casefold()
    assert "https://" not in result.casefold()


def test_html_preserves_unicode_while_escaping_markup(report_data_factory):
    result = render_html_report(
        report_data_factory(
            title="公開バケット",
            remediation="雪☃ & <review>",
            evidence={"説明": "外部公開"},
        )
    )

    assert "公開バケット" in result
    assert "雪☃" in result
    assert "&lt;review&gt;" in result
    assert "<review>" not in result


def test_html_identifies_unrun_and_incomplete_assessments(report_data_factory):
    not_run = render_html_report(report_data_factory(severities=(), errors=None))
    incomplete = render_html_report(
        report_data_factory(severities=(), errors=..., status=ScanStatus.FAILED)
    )

    assert "Assessment not run" in not_run
    assert "Incomplete assessment" in incomplete
    assert "Some evidence could not be evaluated." in incomplete
    assert "scan did not complete successfully" in incomplete
    assert "No findings in this severity category." in incomplete
