"""Create target-safe Boto3 clients for LocalStack and AWS."""

from urllib.parse import urlsplit

import boto3
from botocore.client import BaseClient
from botocore.config import Config as BotocoreConfig

from cspm.config import (
    ConfigurationError,
    CSPMConfig,
    _validate_localstack_endpoint,
    load_config,
)
from cspm.models.enums import TargetType

LOCALSTACK_ACCESS_KEY_ID = "test"
LOCALSTACK_SECRET_ACCESS_KEY = "test"
_DEFAULT_LOCALSTACK_ENDPOINT = "http://localhost:4566"


class UnsupportedTargetError(RuntimeError):
    """Raised when a client is requested for a disabled target."""


def create_client(
    service_name: str,
    config: CSPMConfig | None = None,
    *,
    region_name: str | None = None,
) -> BaseClient:
    """Create a Boto3 client for the explicitly selected target."""
    settings = load_config() if config is None else config
    if settings.target not in (TargetType.LOCALSTACK, TargetType.AWS):
        raise UnsupportedTargetError(
            "Unsupported CSPM target; choose 'localstack' or 'aws'."
        )
    if not service_name.strip():
        raise ValueError("service_name must not be empty or whitespace-only")

    if settings.target is TargetType.LOCALSTACK:
        endpoint = _validate_localstack_endpoint(settings.localstack_endpoint_url)
        client_region = region_name or settings.region
        if client_region != settings.region:
            raise ConfigurationError(
                "LocalStack clients must use the configured CSPM_REGION"
            )
        session = boto3.Session(
            aws_access_key_id=LOCALSTACK_ACCESS_KEY_ID,
            aws_secret_access_key=LOCALSTACK_SECRET_ACCESS_KEY,
            region_name=settings.region,
        )
        return session.client(
            service_name,
            endpoint_url=str(endpoint).rstrip("/"),
            region_name=client_region,
            config=BotocoreConfig(
                connect_timeout=2,
                read_timeout=2,
                retries={"max_attempts": 1},
                proxies={},
            ),
        )

    _validate_aws_endpoint_configuration(settings)

    client_region = region_name or settings.region
    session = boto3.Session(region_name=settings.region)
    return session.client(
        service_name,
        region_name=client_region,
        config=BotocoreConfig(
            connect_timeout=5,
            read_timeout=20,
            retries={"mode": "standard", "max_attempts": 3},
            ignore_configured_endpoint_urls=True,
        ),
    )


def _validate_aws_endpoint_configuration(config: CSPMConfig) -> None:
    """Reject LocalStack endpoint overrides when the AWS target is selected."""
    endpoint = _validate_localstack_endpoint(config.localstack_endpoint_url)
    if str(endpoint).rstrip("/") != _DEFAULT_LOCALSTACK_ENDPOINT:
        raise ConfigurationError(
            "CSPM_LOCALSTACK_ENDPOINT_URL cannot be customized when "
            "CSPM_TARGET=aws"
        )


def _validate_aws_client_endpoint(endpoint_url: object) -> None:
    """Require injected AWS clients to use an HTTPS AWS service endpoint."""
    if not isinstance(endpoint_url, str):
        raise ConfigurationError("AWS collectors require an AWS service endpoint")
    parsed = urlsplit(endpoint_url)
    hostname = parsed.hostname
    aws_suffixes = (
        ".amazonaws.com",
        ".amazonaws.com.cn",
        ".c2s.ic.gov",
        ".sc2s.sgov.gov",
    )
    if (
        parsed.scheme != "https"
        or not hostname
        or not any(hostname.endswith(suffix) for suffix in aws_suffixes)
    ):
        raise ConfigurationError("AWS collectors require an HTTPS AWS service endpoint")
