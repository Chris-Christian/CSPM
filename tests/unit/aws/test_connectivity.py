from unittest.mock import Mock

import pytest
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
)

from cspm.aws import connectivity
from cspm.aws.connectivity import (
    ConnectivityError,
    EndpointUnavailableError,
    verify_connectivity,
)
from cspm.config import load_config
from cspm.models.enums import TargetType


def test_connectivity_calls_sts_and_returns_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.return_value = {
        "Account": "000000000000",
        "Arn": "arn:aws:iam::000000000000:root",
        "UserId": "AKIAIOSFODNN7EXAMPLE",
    }
    create_client = Mock(return_value=client)
    monkeypatch.setattr(connectivity, "create_client", create_client)

    result = verify_connectivity(load_config({}))

    create_client.assert_called_once_with("sts", load_config({}))
    client.get_caller_identity.assert_called_once_with()
    assert result.connected is True
    assert result.account == "000000000000"
    assert result.arn == "arn:aws:iam::000000000000:root"
    assert result.user_id == "AKIAIOSFODNN7EXAMPLE"


def test_aws_connectivity_returns_identity_using_aws_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:root",
        "UserId": "AIDATESTUSER",
    }
    create_client = Mock(return_value=client)
    monkeypatch.setattr(connectivity, "create_client", create_client)
    config = load_config({"CSPM_TARGET": "aws", "CSPM_REGION": "us-west-2"})

    result = verify_connectivity(config)

    create_client.assert_called_once_with("sts", config)
    assert result.account == "123456789012"
    assert config.target is TargetType.AWS


@pytest.mark.parametrize(
    "connection_error",
    [
        EndpointConnectionError(endpoint_url="http://localhost:4566"),
        ConnectTimeoutError(endpoint_url="http://localhost:4566"),
    ],
)
def test_connectivity_reports_unavailable_endpoint(
    monkeypatch: pytest.MonkeyPatch,
    connection_error: BotoCoreError,
) -> None:
    client = Mock()
    client.get_caller_identity.side_effect = connection_error
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(EndpointUnavailableError, match="Could not connect") as error:
        verify_connectivity(load_config({}))

    assert "secret" not in str(error.value)


def test_connectivity_reports_service_error_without_echoing_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "secret-value-must-not-appear",
            }
        },
        "GetCallerIdentity",
    )
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(ConnectivityError, match="AccessDenied") as error:
        verify_connectivity(load_config({}))

    assert not isinstance(error.value, EndpointUnavailableError)
    assert "secret-value-must-not-appear" not in str(error.value)


def test_other_botocore_errors_are_not_classified_as_endpoint_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.side_effect = BotoCoreError()
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(ConnectivityError) as error:
        verify_connectivity(load_config({}))

    assert not isinstance(error.value, EndpointUnavailableError)


def test_invalid_sts_response_is_not_classified_as_endpoint_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.return_value = {"Account": "000000000000"}
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(ConnectivityError, match="incomplete") as error:
        verify_connectivity(load_config({}))

    assert not isinstance(error.value, EndpointUnavailableError)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("Account", "Arn", "UserId")
        for value in (None, "", " \t ", 123)
    ],
)
def test_connectivity_rejects_invalid_identity_values(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    response: dict[str, object] = {
        "Account": "000000000000",
        "Arn": "arn:aws:iam::000000000000:root",
        "UserId": "AKIAIOSFODNN7EXAMPLE",
    }
    response[field] = value
    client = Mock()
    client.get_caller_identity.return_value = response
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(ConnectivityError, match="invalid") as error:
        verify_connectivity(load_config({}))

    assert not isinstance(error.value, EndpointUnavailableError)


def test_unexpected_errors_are_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Mock()
    client.get_caller_identity.side_effect = RuntimeError("unexpected failure")
    monkeypatch.setattr(connectivity, "create_client", Mock(return_value=client))

    with pytest.raises(RuntimeError, match="unexpected failure"):
        verify_connectivity(load_config({}))
