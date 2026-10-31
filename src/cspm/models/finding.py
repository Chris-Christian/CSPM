"""Validated security finding model."""

import math
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, Field, JsonValue, field_validator

from cspm.models.enums import Severity


class Finding(BaseModel):
    """A security finding associated with a scanned resource."""

    finding_id: UUID
    fingerprint: str
    scan_id: UUID
    rule_id: str
    resource_id: str
    title: str
    severity: Severity
    cis_control: str | None = None
    remediation: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    detected_at: datetime

    @field_validator("fingerprint", "rule_id", "resource_id", "title", "remediation")
    @classmethod
    def required_text_must_not_be_blank(cls, value: str) -> str:
        """Reject required text that is empty or contains only whitespace."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("cis_control")
    @classmethod
    def optional_text_must_not_be_blank(cls, value: str | None) -> str | None:
        """Allow an absent CIS control, but reject a blank one."""
        if value is not None and not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("detected_at")
    @classmethod
    def detected_at_must_be_aware_and_normalized(cls, value: datetime) -> datetime:
        """Require an aware detection timestamp and normalize it to UTC."""
        if value.utcoffset() is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("evidence", mode="before")
    @classmethod
    def evidence_must_contain_json_values(cls, value: object) -> object:
        """Reject unsupported or cyclic values in evidence before coercion."""
        if not isinstance(value, dict):
            raise ValueError("evidence must be a dictionary")

        active_containers: set[int] = set()

        def validate_json_value(item: object) -> None:
            if item is None or type(item) in (str, bool, int):
                return
            if type(item) is float:
                if not math.isfinite(item):
                    raise ValueError("evidence floats must be finite")
                return
            if type(item) in (list, dict):
                container_id = id(item)
                if container_id in active_containers:
                    raise ValueError("evidence must not contain cyclic references")
                active_containers.add(container_id)
                try:
                    if type(item) is list:
                        for element in item:
                            validate_json_value(element)
                    else:
                        for key, element in item.items():
                            if type(key) is not str:
                                raise ValueError("evidence object keys must be strings")
                            validate_json_value(element)
                finally:
                    active_containers.remove(container_id)
                return
            raise ValueError("evidence must contain only JSON-compatible values")

        validate_json_value(value)
        return value
