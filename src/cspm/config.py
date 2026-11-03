"""Application configuration loaded from CSPM-prefixed environment variables."""

import os
from collections.abc import Mapping
from typing import Annotated

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from cspm.models.enums import TargetType

_ALLOWED_LOCALSTACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_SENSITIVE_TCP_PORTS = (22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017)
_PORT = Annotated[int, Field(strict=True, ge=1, le=65535)]


class ConfigurationError(ValueError):
    """A safe, user-facing configuration validation error."""


_HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def _validate_localstack_endpoint(value: object) -> AnyHttpUrl:
    """Validate an HTTP endpoint and require one of the approved loopback hosts."""
    try:
        endpoint = _HTTP_URL_ADAPTER.validate_python(value)
    except ValidationError:
        raise ConfigurationError(
            "LocalStack endpoint must be a valid HTTP(S) URL"
        ) from None

    if (
        endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query is not None
        or endpoint.fragment is not None
    ):
        raise ConfigurationError(
            "LocalStack endpoint must not include user information, query, or fragment"
        )

    hostname = endpoint.host
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    if hostname not in _ALLOWED_LOCALSTACK_HOSTS:
        raise ConfigurationError(
            "only loopback LocalStack endpoints are permitted "
            "(localhost, 127.0.0.1, or ::1)"
        )
    return endpoint


class CSPMConfig(BaseModel):
    """Validated target, region, and LocalStack endpoint configuration."""

    target: TargetType = TargetType.LOCALSTACK
    region: str = "us-east-1"
    localstack_endpoint_url: AnyHttpUrl = Field(
        default="http://localhost:4566", validate_default=True
    )
    sensitive_ports: tuple[_PORT, ...] = Field(
        default=_DEFAULT_SENSITIVE_TCP_PORTS, validate_default=True
    )
    sensitive_udp_ports: tuple[_PORT, ...] = Field(default=())

    @field_validator("region")
    @classmethod
    def region_must_not_be_blank(cls, value: str) -> str:
        """Reject an empty or whitespace-only AWS region name."""
        if not value.strip():
            raise ValueError("must not be empty or whitespace-only")
        return value

    @field_validator("localstack_endpoint_url")
    @classmethod
    def endpoint_must_not_include_credentials_or_query_data(
        cls, value: AnyHttpUrl
    ) -> AnyHttpUrl:
        """Restrict LocalStack to loopback and reject URL-carried secrets."""
        return _validate_localstack_endpoint(value)

    @field_validator("sensitive_ports", "sensitive_udp_ports", mode="before")
    @classmethod
    def parse_sensitive_ports(cls, value: object) -> object:
        """Parse comma-separated ports and canonicalize port sequences."""
        if isinstance(value, str):
            if not value.strip():
                return ()
            tokens = value.split(",")
            if any(not token.strip() for token in tokens):
                raise ValueError("ports must be comma-separated integers")
            try:
                value = tuple(int(token.strip()) for token in tokens)
            except ValueError:
                raise ValueError("ports must be comma-separated integers") from None
        return value

    @field_validator("sensitive_ports", "sensitive_udp_ports")
    @classmethod
    def canonicalize_sensitive_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        """Sort and de-duplicate validated port values for deterministic rules."""
        return tuple(sorted(set(value)))


def load_config(environ: Mapping[str, str] | None = None) -> CSPMConfig:
    """Load CSPM settings from the process environment or a supplied mapping."""
    source = os.environ if environ is None else environ
    environment_names = {
        "CSPM_TARGET": "target",
        "CSPM_REGION": "region",
        "CSPM_LOCALSTACK_ENDPOINT_URL": "localstack_endpoint_url",
        "CSPM_SENSITIVE_PORTS": "sensitive_ports",
        "CSPM_SENSITIVE_UDP_PORTS": "sensitive_udp_ports",
    }
    values = {
        field_name: source[environment_name]
        for environment_name, field_name in environment_names.items()
        if environment_name in source
    }

    try:
        return CSPMConfig.model_validate(values)
    except ValidationError as exc:
        details = []
        for error in exc.errors(
            include_input=False, include_context=False, include_url=False
        ):
            field = ".".join(str(part) for part in error["loc"]) or "configuration"
            details.append(f"{field}: {error['msg']}")
        raise ConfigurationError(
            "Invalid CSPM configuration: " + "; ".join(details)
        ) from None
