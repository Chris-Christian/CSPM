import json

import pytest
from pydantic import ValidationError

from cspm.models.enums import Severity
from cspm.models.rule import Rule


def make_rule(**overrides: object) -> Rule:
    values: dict[str, object] = {
        "rule_id": "S3-001",
        "title": "Block public access",
        "resource_type": "s3_bucket",
        "severity": Severity.HIGH,
        "remediation_text": "Enable public access blocking.",
    }
    values.update(overrides)
    return Rule(**values)


def test_rule_valid_construction_without_cis_mapping() -> None:
    rule = make_rule()

    assert rule.cis_control is None
    assert rule.cis_version is None


def test_rule_valid_construction_with_cis_mapping() -> None:
    rule = make_rule(cis_control="1.2.3", cis_version="1.5")

    assert rule.cis_control == "1.2.3"
    assert rule.cis_version == "1.5"


@pytest.mark.parametrize(
    "missing_field",
    ["rule_id", "title", "resource_type", "severity", "remediation_text"],
)
def test_rule_requires_fields(missing_field: str) -> None:
    values: dict[str, object] = {
        "rule_id": "S3-001",
        "title": "Block public access",
        "resource_type": "s3_bucket",
        "severity": Severity.HIGH,
        "remediation_text": "Enable public access blocking.",
    }
    del values[missing_field]

    with pytest.raises(ValidationError):
        Rule(**values)


@pytest.mark.parametrize("severity", ["urgent", "high"])
def test_rule_rejects_invalid_severity(severity: str) -> None:
    with pytest.raises(ValidationError):
        make_rule(severity=severity)


@pytest.mark.parametrize(
    "field", ["rule_id", "title", "resource_type", "remediation_text"]
)
@pytest.mark.parametrize("value", ["", " \t "])
def test_rule_rejects_blank_required_strings(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make_rule(**{field: value})


@pytest.mark.parametrize("field", ["cis_control", "cis_version"])
def test_rule_rejects_blank_optional_cis_values(field: str) -> None:
    with pytest.raises(ValidationError):
        make_rule(**{field: "  "})


@pytest.mark.parametrize(
    ("cis_control", "cis_version"), [("1.2.3", None), (None, "1.5")]
)
def test_rule_requires_cis_mapping_pair(
    cis_control: str | None, cis_version: str | None
) -> None:
    with pytest.raises(ValidationError, match="provided together"):
        make_rule(cis_control=cis_control, cis_version=cis_version)


def test_rule_json_round_trip() -> None:
    rule = make_rule(
        severity=Severity.CRITICAL, cis_control="1.2.3", cis_version="1.5"
    )

    restored = Rule.model_validate_json(rule.model_dump_json())

    assert restored == rule
    assert json.loads(rule.model_dump_json())["severity"] == "CRITICAL"
