"""Shared collector result types and safe AWS error handling."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar
from uuid import UUID

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from cspm.aws.client_factory import UnsupportedTargetError, create_client
from cspm.config import (
    CSPMConfig,
    _validate_localstack_endpoint,
    load_config,
)
from cspm.models.collector import CollectorError, CollectorResult
from cspm.models.enums import CollectorStatus, TargetType
from cspm.models.resource import Resource


@dataclass(frozen=True)
class CollectorCollection:
    """Resources and coverage summary returned by one collector."""

    resources: list[Resource]
    result: CollectorResult


def safe_error(operation: str, exc: Exception) -> CollectorError:
    """Build a non-secret error summary without exposing service messages."""
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        candidate = str(code) if isinstance(code, (str, int)) else "ClientError"
        error_code = (
            candidate
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", candidate)
            else "ClientError"
        )
    elif isinstance(exc, BotoCoreError):
        error_code = type(exc).__name__
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        error_code = "InvalidResponse"
    else:
        error_code = type(exc).__name__
    return CollectorError(
        error_code=error_code or "CollectionError",
        message=f"{operation} failed ({error_code or 'CollectionError'}).",
        operation=operation,
    )


def result_for(
    name: str,
    resources: list[Resource],
    errors: list[CollectorError],
    *,
    primary_failed: bool = False,
) -> CollectorResult:
    """Apply the approved success/partial/failed coverage semantics."""
    if primary_failed or (errors and not resources):
        status = CollectorStatus.FAILED
    elif errors:
        status = CollectorStatus.PARTIAL
    else:
        status = CollectorStatus.SUCCESS
    return CollectorResult(
        collector_name=name,
        status=status,
        resources_discovered=len(resources),
        errors=errors,
    )


class Collector(ABC):
    """Common interface for a read-only resource collector."""

    name: ClassVar[str]
    service_name: ClassVar[str]

    def __init__(
        self, config: CSPMConfig | None = None, client: BaseClient | None = None
    ) -> None:
        self.config: CSPMConfig = config if config is not None else load_config()
        if self.config.target is not TargetType.LOCALSTACK:
            raise UnsupportedTargetError("Resource collectors support LocalStack only.")
        _validate_localstack_endpoint(self.config.localstack_endpoint_url)
        client_meta = getattr(client, "meta", None)
        client_endpoint = getattr(client_meta, "endpoint_url", None)
        if client_endpoint is not None:
            _validate_localstack_endpoint(client_endpoint)
        self._client = client

    @property
    def client(self) -> BaseClient:
        """Return an injected client or create one through the safe factory."""
        if self._client is None:
            self._client = create_client(self.service_name, self.config)
        return self._client

    @abstractmethod
    def collect(self, scan_id: UUID) -> CollectorCollection:
        """Discover resources for a scan without changing cloud state."""
