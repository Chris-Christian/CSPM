"""Shared string enumerations used by CSPM models."""

from enum import StrEnum


class Severity(StrEnum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanStatus(StrEnum):
    """Lifecycle states for a scan."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TargetType(StrEnum):
    """Supported scan target environments."""

    AWS = "aws"
    LOCALSTACK = "localstack"


class CollectorStatus(StrEnum):
    """Outcome of a resource collector run."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
