"""Centralized Boto3 client creation for the LocalStack target."""

import boto3
from botocore.client import BaseClient
from botocore.config import Config as BotocoreConfig

from cspm.config import CSPMConfig, _validate_localstack_endpoint, load_config
from cspm.models.enums import TargetType

LOCALSTACK_ACCESS_KEY_ID = "test"
LOCALSTACK_SECRET_ACCESS_KEY = "test"


class UnsupportedTargetError(RuntimeError):
    """Raised when a client is requested for a disabled target."""


def create_client(service_name: str, config: CSPMConfig | None = None) -> BaseClient:
    """Create an explicitly configured Boto3 client for LocalStack only."""
    settings = load_config() if config is None else config
    if settings.target is not TargetType.LOCALSTACK:
        raise UnsupportedTargetError(
            "Real AWS clients are disabled. Set CSPM_TARGET=localstack to use "
            "the LocalStack endpoint."
        )
    endpoint = _validate_localstack_endpoint(settings.localstack_endpoint_url)
    if not service_name.strip():
        raise ValueError("service_name must not be empty or whitespace-only")

    session = boto3.Session(
        aws_access_key_id=LOCALSTACK_ACCESS_KEY_ID,
        aws_secret_access_key=LOCALSTACK_SECRET_ACCESS_KEY,
        region_name=settings.region,
    )
    return session.client(
        service_name,
        endpoint_url=str(endpoint).rstrip("/"),
        region_name=settings.region,
        config=BotocoreConfig(
            connect_timeout=2, read_timeout=2, retries={"max_attempts": 1}, proxies={}
        ),
    )
