from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from cspm.models.collector import CollectorResult
from cspm.models.enums import CollectorStatus, ScanStatus, TargetType
from cspm.models.scan import Scan


def make_scan(**overrides: object) -> Scan:
    values: dict[str, object] = {
        "scan_id": uuid4(),
        "target": TargetType.AWS,
        "region": "us-east-1",
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "status": ScanStatus.RUNNING,
    }
    values.update(overrides)
    return Scan(**values)


def test_scan_valid_construction_and_optional_completion() -> None:
    scan = make_scan()

    assert isinstance(scan.scan_id, UUID)
    assert scan.completed_at is None
    assert scan.collector_results == []


@pytest.mark.parametrize(
    "missing_field", ["scan_id", "target", "region", "started_at", "status"]
)
def test_scan_requires_fields(missing_field: str) -> None:
    values: dict[str, object] = {
        "scan_id": uuid4(),
        "target": TargetType.AWS,
        "region": "us-east-1",
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "status": ScanStatus.RUNNING,
    }
    del values[missing_field]

    with pytest.raises(ValidationError):
        Scan(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scan_id", "not-a-uuid"),
        ("target", "azure"),
        ("status", "unknown"),
    ],
)
def test_scan_rejects_invalid_uuid_and_enums(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make_scan(**{field: value})


@pytest.mark.parametrize("region", ["", " \t "])
def test_scan_rejects_blank_region(region: str) -> None:
    with pytest.raises(ValidationError):
        make_scan(region=region)


@pytest.mark.parametrize("field", ["started_at", "completed_at"])
def test_scan_rejects_naive_datetimes(field: str) -> None:
    with pytest.raises(ValidationError):
        make_scan(**{field: datetime(2026, 1, 1)})


def test_scan_normalizes_aware_datetimes_to_utc() -> None:
    local_time = timezone(timedelta(hours=5, minutes=30))
    scan = make_scan(
        started_at=datetime(2026, 1, 1, 12, tzinfo=local_time),
        completed_at=datetime(2026, 1, 1, 13, tzinfo=local_time),
    )

    assert scan.started_at == datetime(2026, 1, 1, 6, 30, tzinfo=UTC)
    assert scan.completed_at == datetime(2026, 1, 1, 7, 30, tzinfo=UTC)
    assert scan.started_at.utcoffset() == timedelta(0)
    assert scan.completed_at is not None
    assert scan.completed_at.utcoffset() == timedelta(0)


def test_scan_validates_nested_collector_results() -> None:
    result = CollectorResult(
        collector_name="s3",
        status=CollectorStatus.SUCCESS,
        resources_discovered=1,
    )
    scan = make_scan(collector_results=[result])

    assert scan.collector_results == [result]
    with pytest.raises(ValidationError):
        make_scan(collector_results=[{"collector_name": "s3"}])


def test_scan_collector_results_default_is_independent() -> None:
    first = make_scan()
    second = make_scan()
    first.collector_results.append(
        CollectorResult(
            collector_name="s3",
            status=CollectorStatus.SUCCESS,
            resources_discovered=0,
        )
    )

    assert second.collector_results == []


def test_scan_json_round_trip() -> None:
    scan = make_scan(
        target=TargetType.LOCALSTACK,
        status=ScanStatus.COMPLETED,
        completed_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
        collector_results=[
            CollectorResult(
                collector_name="s3",
                status=CollectorStatus.PARTIAL,
                resources_discovered=2,
            )
        ],
    )

    restored = Scan.model_validate_json(scan.model_dump_json())

    assert restored == scan
    assert restored.target is TargetType.LOCALSTACK
    assert restored.status is ScanStatus.COMPLETED
