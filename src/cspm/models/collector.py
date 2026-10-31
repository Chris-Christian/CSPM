"""Validated models describing collector errors and results."""

from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from cspm.models.enums import CollectorStatus


class CollectorError(BaseModel):
    """A non-secret error reported while collecting resources."""

    error_code: str
    message: str
    operation: str | None = None

    @field_validator("error_code", "message")
    @classmethod
    def required_text_must_not_be_blank(cls, value: str) -> str:
        """Reject required text that is empty or contains only whitespace."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("operation")
    @classmethod
    def operation_must_not_be_blank(cls, value: str | None) -> str | None:
        """Allow an absent operation, but reject blank operation names."""
        if value is not None and not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value


class CollectorResult(BaseModel):
    """Summary of one collector run and any errors it encountered."""

    collector_name: str
    status: CollectorStatus
    resources_discovered: Annotated[int, Field(strict=True, ge=0)]
    errors: list[CollectorError] = Field(default_factory=list)

    @field_validator("collector_name")
    @classmethod
    def collector_name_must_not_be_blank(cls, value: str) -> str:
        """Reject a collector name that is empty or whitespace-only."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value
