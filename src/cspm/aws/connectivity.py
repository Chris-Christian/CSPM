"""Target connectivity verification through the harmless STS identity API."""

import re
from dataclasses import dataclass

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
)

from cspm.aws.client_factory import create_client
from cspm.config import CSPMConfig, load_config
from cspm.models.enums import TargetType


class ConnectivityError(RuntimeError):
    """A safe, actionable error while checking cloud-target connectivity."""


class EndpointUnavailableError(ConnectivityError):
    """Raised when a connection to the configured endpoint cannot be made."""


@dataclass(frozen=True)
class ConnectivityResult:
    """Successful target identity information returned by STS."""

    connected: bool
    account: str
    arn: str
    user_id: str


def verify_connectivity(config: CSPMConfig | None = None) -> ConnectivityResult:
    """Call target STS GetCallerIdentity and return its verified identity."""
    settings = config if config is not None else load_config()
    target_name = "AWS" if settings.target is TargetType.AWS else "LocalStack"
    client = create_client("sts", settings)
    try:
        response = client.get_caller_identity()
    except (EndpointConnectionError, ConnectTimeoutError):
        detail = (
            f"Check CSPM_REGION and the AWS credential profile for {target_name}."
            if settings.target is TargetType.AWS
            else "Start LocalStack and check CSPM_LOCALSTACK_ENDPOINT_URL."
        )
        raise EndpointUnavailableError(
            f"Could not connect to {target_name} STS. {detail}"
        ) from None
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "service error")
        if not isinstance(error_code, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,80}", error_code
        ):
            error_code = "service error"
        raise ConnectivityError(
            f"{target_name} STS rejected GetCallerIdentity ({error_code}). "
            + (
                "Check AWS credentials and permissions."
                if settings.target is TargetType.AWS
                else "Check that LocalStack is running and STS is enabled."
            )
        ) from None
    except BotoCoreError as exc:
        raise ConnectivityError(
            f"Could not complete {target_name} STS connectivity verification. "
            f"({type(exc).__name__})"
        ) from None

    try:
        account = response["Account"]
        arn = response["Arn"]
        user_id = response["UserId"]
    except (KeyError, TypeError):
        raise ConnectivityError(
            f"{target_name} STS returned an incomplete GetCallerIdentity response."
        ) from None

    if any(
        not isinstance(value, str) or not value.strip()
        for value in (account, arn, user_id)
    ):
        raise ConnectivityError(
            f"{target_name} STS returned invalid GetCallerIdentity response values."
        )

    return ConnectivityResult(
        connected=True,
        account=account,
        arn=arn,
        user_id=user_id,
    )
