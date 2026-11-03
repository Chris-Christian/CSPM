import pytest
from pydantic import ValidationError

from cspm.config import ConfigurationError, CSPMConfig, load_config
from cspm.models.enums import TargetType


def test_config_defaults_to_localstack() -> None:
    config = load_config({})

    assert config.target is TargetType.LOCALSTACK
    assert config.region == "us-east-1"
    assert str(config.localstack_endpoint_url).rstrip("/") == "http://localhost:4566"
    assert config.sensitive_ports == (22, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017)
    assert config.sensitive_udp_ports == ()


def test_config_parses_custom_sensitive_tcp_and_udp_ports() -> None:
    config = load_config(
        {
            "CSPM_SENSITIVE_PORTS": "443,22,443",
            "CSPM_SENSITIVE_UDP_PORTS": "161,53",
        }
    )

    assert config.sensitive_ports == (22, 443)
    assert config.sensitive_udp_ports == (53, 161)


@pytest.mark.parametrize(
    "ports",
    ["ssh", "22,,80", "0", "65536", "-1"],
)
def test_config_rejects_invalid_sensitive_port_values(ports: str) -> None:
    with pytest.raises(ConfigurationError, match="sensitive_ports"):
        load_config({"CSPM_SENSITIVE_PORTS": ports})


def test_config_rejects_boolean_ports_in_direct_configuration() -> None:
    with pytest.raises(ValidationError):
        CSPMConfig(sensitive_ports=(True,))


def test_config_loads_explicit_cspm_environment() -> None:
    config = load_config(
        {
            "CSPM_TARGET": "localstack",
            "CSPM_REGION": "eu-west-1",
            "CSPM_LOCALSTACK_ENDPOINT_URL": "http://localhost:4567",
            "AWS_DEFAULT_REGION": "ap-south-1",
        }
    )

    assert config.target is TargetType.LOCALSTACK
    assert config.region == "eu-west-1"
    assert str(config.localstack_endpoint_url).rstrip("/") == "http://localhost:4567"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:4566",
        "http://127.0.0.1:4566",
        "http://[::1]:4566",
    ],
)
def test_config_accepts_loopback_endpoints(endpoint: str) -> None:
    config = load_config({"CSPM_LOCALSTACK_ENDPOINT_URL": endpoint})

    assert str(config.localstack_endpoint_url).rstrip("/") == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.amazonaws.com",
        "http://example.com:4566",
        "http://192.168.1.10:4566",
        "http://localstack:4566",
    ],
)
def test_config_rejects_non_loopback_endpoints(endpoint: str) -> None:
    with pytest.raises(ConfigurationError, match="only loopback LocalStack"):
        load_config({"CSPM_LOCALSTACK_ENDPOINT_URL": endpoint})


def test_config_ignores_ambient_aws_target_variables() -> None:
    config = load_config({"AWS_PROFILE": "some-profile", "AWS_REGION": "eu-west-1"})

    assert config.target is TargetType.LOCALSTACK
    assert config.region == "us-east-1"


def test_config_can_represent_disabled_aws_target() -> None:
    config = load_config({"CSPM_TARGET": "aws"})

    assert config.target is TargetType.AWS


@pytest.mark.parametrize(
    "environment",
    [
        {"CSPM_TARGET": "invalid"},
        {"CSPM_REGION": ""},
        {"CSPM_REGION": " \t "},
        {"CSPM_LOCALSTACK_ENDPOINT_URL": "not a URL"},
        {"CSPM_LOCALSTACK_ENDPOINT_URL": "ftp://localhost:4566"},
        {"CSPM_LOCALSTACK_ENDPOINT_URL": "http://user:secret@localhost:4566"},
    ],
)
def test_config_rejects_invalid_values_without_echoing_input(
    environment: dict[str, str],
) -> None:
    with pytest.raises(ConfigurationError) as error:
        load_config(environment)

    assert "secret" not in str(error.value)


def test_config_environment_is_isolated_between_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "CSPM_TARGET",
        "CSPM_REGION",
        "CSPM_LOCALSTACK_ENDPOINT_URL",
        "CSPM_SENSITIVE_PORTS",
        "CSPM_SENSITIVE_UDP_PORTS",
    ):
        monkeypatch.delenv(name, raising=False)

    default_config = load_config()
    monkeypatch.setenv("CSPM_REGION", "ap-south-1")
    explicit_config = load_config()

    assert default_config.region == "us-east-1"
    assert explicit_config.region == "ap-south-1"
