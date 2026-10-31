"""AWS-compatible client and connectivity helpers."""

from cspm.aws.client_factory import UnsupportedTargetError, create_client
from cspm.aws.connectivity import (
    ConnectivityError,
    ConnectivityResult,
    verify_connectivity,
)

__all__ = [
    "ConnectivityError",
    "ConnectivityResult",
    "UnsupportedTargetError",
    "create_client",
    "verify_connectivity",
]
