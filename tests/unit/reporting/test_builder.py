from datetime import timedelta, timezone
from uuid import uuid4

import pytest

from cspm.reporting import (
    ReportDataError,
    ReportNotFoundError,
    build_report_data,
)


def test_builder_uses_repository_models_and_joins_resource_details(repository_factory):
    repository, scan, resource, finding = repository_factory(assessment="not_run")

    data = build_report_data(
        repository,
        scan.scan_id,
        generated_at=scan.started_at.astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ),
    )

    assert data.scan == scan
    assert data.resources == (resource,)
    assert data.findings[0].finding == finding
    assert data.findings[0].resource == resource
    assert data.assessment_errors is None
    assert data.generated_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    ("assessment", "expected_errors", "has_run", "completed_without_errors"),
    [
        ("not_run", None, False, False),
        ("clean", (), True, True),
        ("errors", 1, True, False),
    ],
)
def test_builder_preserves_assessment_states(
    repository_factory,
    assessment,
    expected_errors,
    has_run,
    completed_without_errors,
):
    repository, scan, _, finding = repository_factory(assessment=assessment)

    data = build_report_data(repository, scan.scan_id)

    if expected_errors is None:
        assert data.assessment_errors is None
    elif expected_errors == ():
        assert data.assessment_errors == ()
    else:
        assert len(data.assessment_errors) == expected_errors
        assert data.assessment_errors[0].finding == finding
    assert data.assessment_has_run is has_run
    assert data.assessment_completed_without_errors is completed_without_errors
    assert data.findings[0].finding == finding


def test_builder_retains_empty_findings_and_assessment_errors(repository_factory):
    repository, scan, _, _ = repository_factory(
        assessment="errors", include_finding=False
    )

    data = build_report_data(repository, scan.scan_id)

    assert data.findings == ()
    assert len(data.assessment_errors) == 1


def test_builder_rejects_missing_scan_and_invalid_generation_time(repository_factory):
    repository, scan, _, _ = repository_factory()
    missing_id = uuid4()

    with pytest.raises(ReportNotFoundError, match=str(missing_id)):
        build_report_data(repository, missing_id)
    with pytest.raises(ReportDataError, match="timezone-aware"):
        build_report_data(
            repository, scan.scan_id, generated_at=scan.started_at.replace(tzinfo=None)
        )
