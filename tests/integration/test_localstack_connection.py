"""Optional real LocalStack STS connectivity test; it never mocks the service."""

import pytest

from cspm.aws.connectivity import EndpointUnavailableError, verify_connectivity
from cspm.config import load_config
from cspm.models.enums import TargetType


@pytest.mark.integration
def test_localstack_sts_get_caller_identity() -> None:
    config = load_config()
    if config.target is not TargetType.LOCALSTACK:
        pytest.fail(
            "CSPM_TARGET must be 'localstack' to run this integration test; "
            "real AWS connections are disabled."
        )
    if config.localstack_endpoint_url.host not in {"localhost", "127.0.0.1", "::1"}:
        pytest.fail("Integration tests only connect to a loopback LocalStack endpoint")

    try:
        result = verify_connectivity(config)
    except EndpointUnavailableError as exc:
        pytest.skip(f"LocalStack is not available: {exc}")

    assert result.connected is True
    assert result.account
    assert result.arn
    assert result.user_id
