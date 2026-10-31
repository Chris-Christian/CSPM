from enum import Enum

import pytest
from pydantic import TypeAdapter, ValidationError

from cspm.models.enums import CollectorStatus, ScanStatus, Severity, TargetType


@pytest.mark.parametrize(
    ("enum_type", "expected"),
    [
        (
            Severity,
            {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"},
        ),
        (
            ScanStatus,
            {"RUNNING": "running", "COMPLETED": "completed", "FAILED": "failed"},
        ),
        (TargetType, {"AWS": "aws", "LOCALSTACK": "localstack"}),
        (
            CollectorStatus,
            {"SUCCESS": "success", "PARTIAL": "partial", "FAILED": "failed"},
        ),
    ],
)
def test_enum_members_and_serialized_values(
    enum_type: type[Enum], expected: dict[str, str]
) -> None:
    assert {member.name: member.value for member in enum_type} == expected


@pytest.mark.parametrize(
    ("enum_type", "invalid_value"),
    [
        (Severity, "critical"),
        (ScanStatus, "unknown"),
        (TargetType, "azure"),
        (CollectorStatus, "unknown"),
    ],
)
def test_invalid_enum_values_are_rejected(
    enum_type: type[Enum], invalid_value: str
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(enum_type).validate_python(invalid_value)
