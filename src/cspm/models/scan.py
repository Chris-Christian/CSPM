"""Validated scan metadata models."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from cspm.models.collector import CollectorResult
from cspm.models.enums import ScanStatus, TargetType


class Scan(BaseModel):
    """Metadata and collector summaries for one CSPM scan."""

    scan_id: UUID
    target: TargetType
    region: str
    started_at: datetime
    completed_at: datetime | None = None
    status: ScanStatus
    collector_results: list[CollectorResult] = Field(default_factory=list)

    @field_validator("region")
    @classmethod
    def region_must_not_be_blank(cls, value: str) -> str:
        """Reject a region that is empty or contains only whitespace."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def datetime_must_be_aware_and_normalized(
        cls, value: datetime | None
    ) -> datetime | None:
        """Require timezone-aware timestamps and normalize them to UTC."""
        if value is None:
            return None
        if value.utcoffset() is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(UTC)
