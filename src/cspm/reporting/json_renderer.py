"""Deterministic JSON report rendering."""

import json

from cspm.reporting.data import ReportData
from cspm.reporting.exceptions import ReportRenderError
from cspm.reporting.serialization import report_document


def render_json_report(data: ReportData) -> str:
    """Render a complete report as valid, deterministic JSON text."""
    try:
        return (
            json.dumps(
                report_document(data),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
    except (TypeError, ValueError, RecursionError):
        raise ReportRenderError("report data could not be serialized as JSON") from None
