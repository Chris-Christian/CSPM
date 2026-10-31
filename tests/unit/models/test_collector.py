import json

import pytest
from pydantic import ValidationError

from cspm.models.collector import CollectorError, CollectorResult
from cspm.models.enums import CollectorStatus


def test_collector_error_valid_construction_and_optional_operation() -> None:
    error = CollectorError(error_code="AccessDenied", message="Request denied")

    assert error.error_code == "AccessDenied"
    assert error.operation is None
    assert CollectorError(
        error_code="Throttled", message="Try again", operation="ListBuckets"
    ).operation == "ListBuckets"


@pytest.mark.parametrize(
    "field_values",
    [
        {"error_code": "", "message": "failure"},
        {"error_code": "   ", "message": "failure"},
        {"error_code": "Failure", "message": ""},
        {"error_code": "Failure", "message": " \t "},
        {"error_code": "Failure", "message": "failure", "operation": "  "},
    ],
)
def test_collector_error_rejects_blank_text(field_values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        CollectorError(**field_values)


def test_collector_error_json_round_trip() -> None:
    error = CollectorError(
        error_code="AccessDenied", message="Request denied", operation="ListBuckets"
    )

    assert CollectorError.model_validate_json(error.model_dump_json()) == error
    assert json.loads(error.model_dump_json()) == error.model_dump(mode="json")


def test_collector_result_valid_construction() -> None:
    result = CollectorResult(
        collector_name="s3", status=CollectorStatus.SUCCESS, resources_discovered=3
    )

    assert result.resources_discovered == 3
    assert result.errors == []


@pytest.mark.parametrize("status", list(CollectorStatus))
def test_collector_result_accepts_every_status(status: CollectorStatus) -> None:
    assert CollectorResult(
        collector_name="s3", status=status, resources_discovered=0
    ).status is status


@pytest.mark.parametrize("count", [-1, True, False])
def test_collector_result_rejects_invalid_resource_counts(count: int | bool) -> None:
    with pytest.raises(ValidationError):
        CollectorResult(
            collector_name="s3",
            status=CollectorStatus.SUCCESS,
            resources_discovered=count,
        )


def test_collector_result_rejects_empty_collector_name() -> None:
    with pytest.raises(ValidationError):
        CollectorResult(
            collector_name="  ", status=CollectorStatus.SUCCESS, resources_discovered=0
        )


def test_collector_result_errors_default_is_independent() -> None:
    first = CollectorResult(
        collector_name="s3", status=CollectorStatus.SUCCESS, resources_discovered=0
    )
    second = CollectorResult(
        collector_name="iam", status=CollectorStatus.SUCCESS, resources_discovered=0
    )

    first.errors.append(CollectorError(error_code="Denied", message="Denied"))

    assert second.errors == []


def test_collector_result_accepts_multiple_validated_errors() -> None:
    errors = [
        CollectorError(error_code="Denied", message="One"),
        CollectorError(error_code="Timeout", message="Two"),
    ]
    result = CollectorResult(
        collector_name="s3",
        status=CollectorStatus.PARTIAL,
        resources_discovered=2,
        errors=errors,
    )

    assert result.errors == errors


def test_collector_result_rejects_invalid_nested_errors() -> None:
    with pytest.raises(ValidationError):
        CollectorResult.model_validate(
            {
                "collector_name": "s3",
                "status": "partial",
                "resources_discovered": 1,
                "errors": [{"error_code": "", "message": "Failure"}],
            }
        )


def test_collector_result_json_round_trip() -> None:
    result = CollectorResult(
        collector_name="s3",
        status=CollectorStatus.PARTIAL,
        resources_discovered=2,
        errors=[CollectorError(error_code="Denied", message="Request denied")],
    )

    restored = CollectorResult.model_validate_json(result.model_dump_json())

    assert restored == result
    assert json.loads(result.model_dump_json())["status"] == "partial"
