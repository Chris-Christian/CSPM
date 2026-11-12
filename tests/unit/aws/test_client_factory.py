from unittest.mock import Mock

import boto3
import pytest

from cspm.aws.client_factory import (
    LOCALSTACK_ACCESS_KEY_ID,
    LOCALSTACK_SECRET_ACCESS_KEY,
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


def test_aws_client_uses_standard_credentials_and_no_custom_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock()
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(boto3, "Session", session_factory)
    config = load_config({"CSPM_TARGET": "aws", "CSPM_REGION": "eu-west-1"})

    client = create_client("sts", config)

    assert client is session.client.return_value
    session_factory.assert_called_once_with(region_name="eu-west-1")
    args, kwargs = session.client.call_args
    assert args == ("sts",)
    assert kwargs["region_name"] == "eu-west-1"
    assert "endpoint_url" not in kwargs
    assert "aws_access_key_id" not in kwargs
    assert "aws_secret_access_key" not in kwargs
    assert kwargs["config"].ignore_configured_endpoint_urls is True
    assert kwargs["config"].connect_timeout > 2
    assert kwargs["config"].retries == {"mode": "standard", "max_attempts": 3}


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:9999",
        "https://sts.amazonaws.com",
        "http://192.168.1.10:4566",
    ],
)
def test_aws_client_rejects_custom_endpoint_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    session_factory = Mock()
    monkeypatch.setattr(boto3, "Session", session_factory)
    config = load_config({"CSPM_TARGET": "aws"})
    config.localstack_endpoint_url = endpoint  # type: ignore[assignment]

    with pytest.raises(ConfigurationError):
        create_client("sts", config)

    session_factory.assert_not_called()


def test_aws_client_accepts_explicit_regional_client_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock()
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(boto3, "Session", session_factory)
    config = load_config({"CSPM_TARGET": "aws", "CSPM_REGION": "us-east-1"})

    create_client("s3", config, region_name="eu-west-1")

    assert session.client.call_args.kwargs["region_name"] == "eu-west-1"
    assert session_factory.call_args.kwargs == {"region_name": "us-east-1"}


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
