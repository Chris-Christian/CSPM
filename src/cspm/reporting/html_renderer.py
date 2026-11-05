"""Self-contained, autoescaped HTML report rendering with Jinja2."""

import json
from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, TemplateError

from cspm.reporting.data import SEVERITY_ORDER, ReportData
from cspm.reporting.exceptions import ReportRenderError
from cspm.reporting.serialization import report_document


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("cspm.reporting", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _safe_unicode(value: Any) -> Any:
    if isinstance(value, str):
        return value.encode("utf-8", errors="backslashreplace").decode("utf-8")
    if isinstance(value, dict):
        return {key: _safe_unicode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_unicode(item) for item in value]
    return value


def render_html_report(data: ReportData) -> str:
    """Render a standalone HTML report; all dynamic values remain autoescaped."""
    try:
        document = _safe_unicode(report_document(data))
        groups = {severity.value: [] for severity in SEVERITY_ORDER}
        resources_by_finding = {
            str(item.finding.finding_id): item.resource for item in data.findings
        }
        for finding in document["findings"]:
            resource = resources_by_finding[finding["finding_id"]]
            finding["evidence_json"] = json.dumps(
                finding["evidence"],
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            finding["resource_metadata_json"] = json.dumps(
                resource.raw_metadata,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            finding["resource_tags_json"] = json.dumps(
                resource.tags,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            groups[finding["severity"]].append(finding)
        template = _environment().get_template("report.html.j2")
        return template.render(report=document, finding_groups=groups)
    except (KeyError, TypeError, ValueError, RecursionError, TemplateError) as exc:
        raise ReportRenderError("report data could not be rendered as HTML") from exc
