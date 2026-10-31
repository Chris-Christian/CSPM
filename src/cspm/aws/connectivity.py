"""LocalStack connectivity verification through the harmless STS identity API."""

from dataclasses import dataclass

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
)

from cspm.aws.client_factory import create_client
from cspm.config import CSPMConfig


class ConnectivityError(RuntimeError):
    """A safe, actionable error while checking LocalStack connectivity."""


class EndpointUnavailableError(ConnectivityError):
    """Raised when a connection to the configured endpoint cannot be made."""


@dataclass(frozen=True)
class ConnectivityResult:
    """Successful LocalStack identity information returned by STS."""

    connected: bool
    account: str
    arn: str
    user_id: str


def verify_connectivity(config: CSPMConfig | None = None) -> ConnectivityResult:
    """Call LocalStack STS GetCallerIdentity and return its identity response."""
    client = create_client("sts", config)
    try:
        response = client.get_caller_identity()
    except (EndpointConnectionError, ConnectTimeoutError):
        raise EndpointUnavailableError(
            "Could not connect to LocalStack STS. Start LocalStack and check "
            "CSPM_LOCALSTACK_ENDPOINT_URL."
        ) from None
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "service error")
        raise ConnectivityError(
            f"LocalStack STS rejected GetCallerIdentity ({error_code}). "
            "Check that LocalStack is running and STS is enabled."
        ) from None
    except BotoCoreError as exc:
        raise ConnectivityError(
            "Could not reach LocalStack STS. Start the LocalStack service and "
            "check CSPM_LOCALSTACK_ENDPOINT_URL. "
            f"({type(exc).__name__})"
        ) from None

    try:
        account = response["Account"]
        arn = response["Arn"]
        user_id = response["UserId"]
    except (KeyError, TypeError):
        raise ConnectivityError(
            "LocalStack STS returned an incomplete GetCallerIdentity response."
        ) from None

    if any(
        not isinstance(value, str) or not value.strip()
        for value in (account, arn, user_id)
    ):
        raise ConnectivityError(
            "LocalStack STS returned invalid GetCallerIdentity response values."
        )

    return ConnectivityResult(
        connected=True,
        account=account,
        arn=arn,
        user_id=user_id,
    )
