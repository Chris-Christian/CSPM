from types import SimpleNamespace
from uuid import UUID

import pytest

from cspm.aws.client_factory import UnsupportedTargetError
from cspm.collectors.base import Collector, CollectorCollection
from cspm.config import ConfigurationError, load_config


class ConcreteCollector(Collector):
    name = "test"
    service_name = "sts"

    def collect(self, scan_id: UUID) -> CollectorCollection:
        raise NotImplementedError


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.amazonaws.com",
        "https://example.com",
        "http://192.168.1.10:4566",
    ],
)
def test_collector_rejects_injected_boto_clients_with_non_loopback_endpoints(
    endpoint: str,
) -> None:
    client = SimpleNamespace(meta=SimpleNamespace(endpoint_url=endpoint))

    with pytest.raises(ConfigurationError, match="only loopback LocalStack"):
        ConcreteCollector(load_config({}), client=client)


def test_collector_rejects_aws_target_even_with_an_injected_client() -> None:
    config = load_config({"CSPM_TARGET": "aws"})

    with pytest.raises(UnsupportedTargetError, match="LocalStack only"):
        ConcreteCollector(config, client=object())


def test_collector_accepts_injected_loopback_boto_client() -> None:
    client = SimpleNamespace(meta=SimpleNamespace(endpoint_url="http://[::1]:4566"))

    assert ConcreteCollector(load_config({}), client=client).client is client
