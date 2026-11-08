"""Markdown report rendering with safe handling for untrusted report text."""

import html
import json
import re

from cspm.reporting.data import SEVERITY_ORDER, FindingReport, ReportData
from cspm.reporting.exceptions import ReportRenderError
from cspm.reporting.serialization import report_document


def _safe_text(value: object) -> str:
    text = str(value)
    return text.encode("utf-8", errors="backslashreplace").decode("utf-8")


def _inline(value: object) -> str:
    text = html.escape(_safe_text(value), quote=False)
    text = re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text)
    return text.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")


def _code(value: object) -> str:
    text = _safe_text(value)
    runs = [len(run) for run in re.findall(r"`+", text)]
    delimiter = "`" * max(1, max(runs, default=0) + 1)
    padding = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"


def _code_fence(text: str) -> tuple[str, str]:
    runs = [len(run) for run in re.findall(r"`+", text)]
    fence = "`" * max(3, max(runs, default=0) + 1)
    return fence, text


def _safe_json_value(value):
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, dict):
        return {key: _safe_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json_value(item) for item in value]
    return value


def _evidence(value: object) -> str:
    try:
        return json.dumps(
            _safe_json_value(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
    except (TypeError, ValueError, RecursionError):
        raise ReportRenderError(
            "finding evidence could not be rendered as JSON"
        ) from None


def _finding_section(item: FindingReport) -> list[str]:
    finding = item.finding
    lines = [
        f"### {_inline(finding.title)}",
        "",
        f"- **Finding ID:** {_code(finding.finding_id)}",
        f"- **Resource:** {_code(item.resource.resource_id)} "
        f"({_inline(item.resource.resource_type)})",
        f"- **Rule:** {_code(finding.rule_id)}",
        f"- **Fingerprint:** {_code(finding.fingerprint)}",
        f"- **Detected:** {_inline(finding.detected_at.isoformat())}",
    ]
    if finding.cis_control is not None:
        lines.append(f"- **CIS control:** {_inline(finding.cis_control)}")
    fence, evidence = _code_fence(_evidence(finding.evidence))
    lines.extend(
        [
            "",
            "**Evidence**",
            "",
            f"{fence}json",
            evidence,
            fence,
            "",
            "**Remediation**",
            "",
            _inline(finding.remediation),
            "",
        ]
    )
    return lines


def render_markdown_report(data: ReportData) -> str:
    """Render a readable Markdown report without compliance overclaims."""
    document = report_document(data)
    scan = document["scan"]
    inventory = document["inventory"]
    assessment = document["assessment"]
    lines = [
        "# CSPM Security Assessment Report",
        "",
        "**READ-ONLY assessment report**",
        "",
        "## Scan metadata",
        "",
        f"- **Scan ID:** {_code(scan['scan_id'])}",
        f"- **Target:** {_inline(scan['target'])}",
        f"- **Region:** {_inline(scan['region'])}",
        f"- **Status:** {_inline(scan['status'])}",
        f"- **Started:** {_inline(scan['started_at'])}",
        "- **Completed:** "
        + (_inline(scan["completed_at"]) if scan["completed_at"] else "Not recorded"),
        f"- **Report generated:** {_inline(document['report_generated_at'])}",
        "",
        "## Resource summary",
        "",
        f"Total resources discovered: **{inventory['total_resources']}**",
        "",
    ]
    if inventory["resource_counts_by_type"]:
        lines.extend(["| Resource type | Count |", "| --- | ---: |"])
        lines.extend(
            f"| {_inline(resource_type)} | {count} |"
            for resource_type, count in inventory["resource_counts_by_type"].items()
        )
    else:
        lines.append("No resources were recorded for this scan.")

    lines.extend(
        [
            "",
            "## Assessment summary",
            "",
            f"Total findings: **{assessment['total_findings']}**",
            "",
            "| Severity | Findings |",
            "| --- | ---: |",
        ]
    )
    lines.extend(
        f"| {severity.value} | {data.severity_counts[severity]} |"
        for severity in SEVERITY_ORDER
    )
    lines.extend(["", "## Collector coverage", ""])
    if data.scan.collector_results:
        lines.extend(
            f"- {_code(result.collector_name)}: {_inline(result.status.value)} "
            f"({result.resources_discovered} resource(s), "
            f"{len(result.errors)} error(s))"
            for result in data.scan.collector_results
        )
    else:
        lines.append("**No collector coverage was recorded for this scan.**")
    if not data.collectors_complete:
        lines.extend(
            [
                "",
                "**Incomplete discovery:** one or more collectors did not fully "
                "succeed, or none were recorded. Resources may be missing, so zero "
                "findings does not mean clean.",
            ]
        )
    if data.assessment_errors is None:
        lines.extend(
            [
                "",
                "**Assessment not run:** no persisted assessment outcome is available.",
            ]
        )
    elif data.assessment_errors:
        lines.extend(
            [
                "",
                f"**Incomplete assessment:** {len(data.assessment_errors)} "
                "evaluation error(s) were recorded. Findings below remain visible.",
            ]
        )
    elif data.scan.status.value != "completed":
        lines.extend(
            [
                "",
                "No assessment errors were recorded, but the scan lifecycle status "
                f"is **{_inline(data.scan.status.value)}**. The scan did not complete "
                "successfully; this report makes no compliance claim.",
            ]
        )
    elif not data.collectors_complete:
        lines.extend(
            [
                "",
                "No rule evaluation errors were recorded, but discovery was "
                "incomplete (see collector coverage); this report makes no "
                "compliance claim.",
            ]
        )
    else:
        lines.extend(
            [
                "",
                "Assessment ran without recorded evaluation errors. This is not a "
                "compliance certification.",
            ]
        )

    if data.assessment_errors:
        lines.extend(["", "### Assessment errors", ""])
        for error in data.assessment_errors:
            lines.extend(
                [
                    f"- **{_inline(error.error_code or 'EvaluationError')}:** "
                    f"{_inline(error.message or 'No error message recorded')} "
                    f"(resource {_code(error.resource_id)}, "
                    f"type `{_inline(error.resource_type)}`, "
                    f"rule {_code(error.rule_id or 'unspecified')})",
                ]
            )

    lines.extend(["", "## Findings by severity", ""])
    for severity in SEVERITY_ORDER:
        group = data.findings_by_severity[severity]
        lines.extend(
            [
                f"### {severity.value} ({len(group)})",
                "",
            ]
        )
        if not group:
            lines.extend(["No findings in this severity category.", ""])
        for item in group:
            lines.extend(_finding_section(item))

    return "\n".join(lines).rstrip() + "\n"
