from unittest.mock import Mock

import boto3
import pytest

from cspm.aws.client_factory import (
    LOCALSTACK_ACCESS_KEY_ID,
    LOCALSTACK_SECRET_ACCESS_KEY,
    UnsupportedTargetError,
    create_client,
)
from cspm.config import ConfigurationError, load_config


def test_client_factory_uses_explicit_localstack_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock()
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(boto3, "Session", session_factory)
    config = load_config({"CSPM_REGION": "eu-west-1"})

    client = create_client("sts", config)

    assert client is session.client.return_value
    session_factory.assert_called_once_with(
        aws_access_key_id=LOCALSTACK_ACCESS_KEY_ID,
        aws_secret_access_key=LOCALSTACK_SECRET_ACCESS_KEY,
        region_name="eu-west-1",
    )
    call = session.client.call_args
    assert call.args == ("sts",)
    assert call.kwargs["endpoint_url"] == "http://localhost:4566"
    assert call.kwargs["region_name"] == "eu-west-1"
    assert call.kwargs["config"].connect_timeout == 2
    client.assert_not_called()


def test_client_factory_rejects_aws_before_creating_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_factory = Mock()
    monkeypatch.setattr(boto3, "Session", session_factory)

    with pytest.raises(UnsupportedTargetError, match="Real AWS clients are disabled"):
        create_client("sts", load_config({"CSPM_TARGET": "aws"}))

    session_factory.assert_not_called()


def test_client_factory_rejects_non_loopback_endpoint_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_factory = Mock()
    monkeypatch.setattr(boto3, "Session", session_factory)
    monkeypatch.setenv("CSPM_TARGET", "localstack")
    monkeypatch.setenv(
        "CSPM_LOCALSTACK_ENDPOINT_URL", "https://sts.amazonaws.com"
    )

    with pytest.raises(ConfigurationError, match="only loopback LocalStack"):
        create_client("sts")

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.amazonaws.com",
        "http://example.com:4566",
        "http://192.168.1.10:4566",
    ],
)
def test_client_factory_revalidates_mutated_endpoint_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    session = Mock()
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(boto3, "Session", session_factory)
    config = load_config({})
    config.localstack_endpoint_url = endpoint  # type: ignore[assignment]

    with pytest.raises(ConfigurationError, match="only loopback LocalStack"):
        create_client("sts", config)

    session_factory.assert_not_called()
    session.client.assert_not_called()


def test_client_factory_rejects_blank_service_name() -> None:
    with pytest.raises(ValueError, match="service_name"):
        create_client(" ", load_config({}))
