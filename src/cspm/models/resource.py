"""Validated discovered-resource metadata model."""

import math
from uuid import UUID

from pydantic import BaseModel, Field, JsonValue, StrictStr, field_validator


class Resource(BaseModel):
    """A discovered resource and its JSON-compatible metadata."""

    scan_id: UUID
    resource_id: str
    resource_type: str
    region: str
    raw_metadata: dict[str, JsonValue] = Field(default_factory=dict)
    tags: dict[StrictStr, StrictStr] = Field(default_factory=dict)

    @field_validator("resource_id", "resource_type", "region")
    @classmethod
    def required_text_must_not_be_blank(cls, value: str) -> str:
        """Reject required text that is empty or contains only whitespace."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("raw_metadata", mode="before")
    @classmethod
    def metadata_must_contain_json_values(cls, value: object) -> object:
        """Reject values that JSON cannot represent without coercion."""
        if not isinstance(value, dict):
            raise ValueError("raw_metadata must be a dictionary")

        active_containers: set[int] = set()

        def validate_json_value(item: object) -> None:
            if item is None or type(item) in (str, bool, int):
                return
            if type(item) is float:
                if not math.isfinite(item):
                    raise ValueError("raw_metadata floats must be finite")
                return
            if type(item) in (list, dict):
                container_id = id(item)
                if container_id in active_containers:
                    raise ValueError("raw_metadata must not contain cyclic references")
                active_containers.add(container_id)
                try:
                    if type(item) is list:
                        for element in item:
                            validate_json_value(element)
                    else:
                        for key, element in item.items():
                            if type(key) is not str:
                                raise ValueError(
                                    "raw_metadata object keys must be strings"
                                )
                            validate_json_value(element)
                finally:
                    active_containers.remove(container_id)
                return
            raise ValueError("raw_metadata must contain only JSON-compatible values")

        validate_json_value(value)
        return value
