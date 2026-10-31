import json
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from cspm.models.enums import Severity
from cspm.models.finding import Finding


def make_finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "finding_id": uuid4(),
        "fingerprint": "v1:abc123",
        "scan_id": uuid4(),
        "rule_id": "S3-001",
        "resource_id": "bucket-123",
        "title": "Public bucket",
        "severity": Severity.HIGH,
        "remediation": "Restrict public access.",
        "detected_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return Finding(**values)


def test_finding_valid_construction_and_optional_cis_control() -> None:
    finding = make_finding()

    assert isinstance(finding.finding_id, UUID)
    assert finding.cis_control is None
    assert finding.evidence == {}

    mapped = make_finding(cis_control="1.2.3")
    assert mapped.cis_control == "1.2.3"


@pytest.mark.parametrize(
    "missing_field",
    [
        "finding_id",
        "fingerprint",
        "scan_id",
        "rule_id",
        "resource_id",
        "title",
        "severity",
        "remediation",
        "detected_at",
    ],
)
def test_finding_requires_fields(missing_field: str) -> None:
    values: dict[str, object] = {
        "finding_id": uuid4(),
        "fingerprint": "v1:abc123",
        "scan_id": uuid4(),
        "rule_id": "S3-001",
        "resource_id": "bucket-123",
        "title": "Public bucket",
        "severity": Severity.HIGH,
        "remediation": "Restrict public access.",
        "detected_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    del values[missing_field]

    with pytest.raises(ValidationError):
        Finding(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("finding_id", "not-a-uuid"),
        ("scan_id", "not-a-uuid"),
        ("severity", "urgent"),
    ],
)
def test_finding_rejects_invalid_uuid_and_severity(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(**{field: value})


@pytest.mark.parametrize(
    "field",
    ["fingerprint", "rule_id", "resource_id", "title", "remediation"],
)
@pytest.mark.parametrize("value", ["", " \t "])
def test_finding_rejects_blank_required_strings(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(**{field: value})


def test_finding_rejects_blank_optional_cis_control() -> None:
    with pytest.raises(ValidationError):
        make_finding(cis_control="  ")


@pytest.mark.parametrize("timestamp", [datetime(2026, 1, 1)])
def test_finding_rejects_naive_detected_at(timestamp: datetime) -> None:
    with pytest.raises(ValidationError):
        make_finding(detected_at=timestamp)


def test_finding_normalizes_detected_at_to_utc() -> None:
    offset = timezone(timedelta(hours=-4))
    finding = make_finding(detected_at=datetime(2026, 1, 1, 12, tzinfo=offset))

    assert finding.detected_at == datetime(2026, 1, 1, 16, tzinfo=UTC)
    assert finding.detected_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "evidence",
    [
        {"value": object()},
        {"value": (1, 2)},
        {1: "non-string key"},
        {"nested": {False: "non-string key"}},
        {"value": float("nan")},
        {"value": float("inf")},
    ],
)
def test_finding_rejects_non_json_evidence(evidence: object) -> None:
    with pytest.raises(ValidationError):
        make_finding(evidence=evidence)


def test_finding_rejects_cyclic_evidence() -> None:
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)

    with pytest.raises(ValidationError, match="cyclic references"):
        make_finding(evidence={"items": cyclic_list})

    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict

    with pytest.raises(ValidationError, match="cyclic references"):
        make_finding(evidence={"nested": cyclic_dict})


def test_finding_evidence_default_is_independent() -> None:
    first = make_finding()
    second = make_finding()
    first.evidence["source"] = "test"

    assert second.evidence == {}


def test_finding_json_round_trip() -> None:
    finding = make_finding(
        severity=Severity.CRITICAL,
        cis_control="1.2.3",
        evidence={"public": True, "details": ["acl", {"access": "open"}]},
    )

    restored = Finding.model_validate_json(finding.model_dump_json())

    assert restored == finding
    assert json.loads(finding.model_dump_json())["severity"] == "CRITICAL"
