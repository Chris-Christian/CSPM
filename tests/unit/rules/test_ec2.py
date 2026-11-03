"""Tests for sensitive-port security-group ingress rules."""

from uuid import uuid4

import pytest

from cspm.config import load_config
from cspm.models.resource import Resource
from cspm.rules import AssessmentEngine, EvaluationStatus
from cspm.rules.ec2 import (
    EC2SensitiveIpv4IngressRule,
    EC2SensitiveIpv6IngressRule,
)


def make_group(ingress: object, **metadata: object) -> Resource:
    raw_metadata: dict[str, object] = {"ingress": ingress}
    raw_metadata.update(metadata)
    return Resource(
        scan_id=uuid4(),
        resource_id="sg-test",
        resource_type="security_group",
        region="us-east-1",
        raw_metadata=raw_metadata,
    )


def tcp_rule(
    from_port: object = 22,
    to_port: object = 22,
    cidrs: list[object] | None = None,
) -> dict[str, object]:
    return {
        "IpProtocol": "tcp",
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": cidrs if cidrs is not None else [{"CidrIp": "0.0.0.0/0"}],
    }


def ipv4_rule(udp_ports: tuple[int, ...] = ()) -> EC2SensitiveIpv4IngressRule:
    config = load_config({})
    return EC2SensitiveIpv4IngressRule(config.sensitive_ports, udp_ports)


def ipv6_rule(udp_ports: tuple[int, ...] = ()) -> EC2SensitiveIpv6IngressRule:
    config = load_config({})
    return EC2SensitiveIpv6IngressRule(config.sensitive_ports, udp_ports)


def test_ipv4_sensitive_tcp_port_is_a_finding() -> None:
    result = ipv4_rule().evaluate(make_group([tcp_rule()]))

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["address_family"] == "IPv4"
    assert result.evidence["exposures"][0]["sensitive_ports"] == [22]


def test_non_sensitive_tcp_port_and_private_cidr_pass() -> None:
    assert (
        ipv4_rule().evaluate(make_group([tcp_rule(8080, 8080)])).status
        is EvaluationStatus.PASSED
    )
    assert ipv4_rule().evaluate(
        make_group([tcp_rule(cidrs=[{"CidrIp": "10.0.0.0/8"}])])
    ).status is EvaluationStatus.PASSED


def test_ranges_overlap_sensitive_port_and_multiple_ranges_are_checked() -> None:
    result = ipv4_rule().evaluate(
        make_group(
            [
                tcp_rule(
                    20,
                    24,
                    [
                        {"CidrIp": "192.0.2.0/24"},
                        {"CidrIp": "0.0.0.0/0"},
                    ],
                )
            ]
        )
    )

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["exposures"][0]["sensitive_ports"] == [22, 23]


def test_udp_requires_explicit_udp_configuration() -> None:
    udp = {
        "IpProtocol": "udp",
        "FromPort": 53,
        "ToPort": 53,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    assert ipv4_rule().evaluate(make_group([udp])).status is EvaluationStatus.PASSED
    assert (
        ipv4_rule((53,)).evaluate(make_group([udp])).status
        is EvaluationStatus.FINDING
    )


def test_all_protocol_rule_covers_the_configured_port_baseline() -> None:
    all_protocols = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}

    result = ipv4_rule().evaluate(make_group([all_protocols]))

    assert result.status is EvaluationStatus.FINDING
    assert 22 in result.evidence["exposures"][0]["sensitive_ports"]


@pytest.mark.parametrize(
    "permission",
    [
        {"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": True, "ToPort": 22},
        {"IpProtocol": "tcp", "FromPort": 1024, "ToPort": 22},
    ],
    ids=["missing-ports", "boolean-port", "reversed-range"],
)
def test_missing_or_invalid_port_values_are_evaluation_errors(permission: dict) -> None:
    result = ipv4_rule().evaluate(make_group([permission]))

    assert result.status is EvaluationStatus.ERROR
    assert result.error_code == "InvalidIngressPortRange"


def test_invalid_ranges_and_missing_ingress_are_errors() -> None:
    bad_cidr = ipv4_rule().evaluate(make_group([tcp_rule(cidrs=[{"CidrIp": "bad"}])]))
    missing = ipv4_rule().evaluate(make_group(None))
    unavailable = ipv4_rule().evaluate(make_group([], ingress_status="error"))

    assert bad_cidr.status is EvaluationStatus.ERROR
    assert missing.status is EvaluationStatus.ERROR
    assert unavailable.status is EvaluationStatus.ERROR


@pytest.mark.parametrize("reverse", [False, True])
def test_confirmed_ingress_finding_survives_malformed_permission(reverse: bool) -> None:
    ingress: list[object] = [tcp_rule(), None]
    if reverse:
        ingress.reverse()

    result = AssessmentEngine(rules=[ipv4_rule()]).evaluate(
        [make_group(ingress)]
    )

    assert len(result.findings) == 1
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "InvalidIngressPermission"
    assert result.errors[0].finding == result.findings[0]
    assert result.is_complete is False


def test_egress_only_rules_do_not_trigger_ingress_findings() -> None:
    resource = make_group([], egress=[tcp_rule()])

    assert ipv4_rule().evaluate(resource).status is EvaluationStatus.PASSED


def test_ipv6_exposure_is_separate_from_ipv4() -> None:
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    resource = make_group([permission])

    assert ipv4_rule().evaluate(resource).status is EvaluationStatus.PASSED
    ipv6_result = ipv6_rule().evaluate(resource)
    assert ipv6_result.status is EvaluationStatus.FINDING
    assert ipv6_result.evidence["address_family"] == "IPv6"


def test_no_sensitive_ports_is_not_reported_as_a_clean_assessment() -> None:
    result = EC2SensitiveIpv4IngressRule((), ()).evaluate(make_group([]))

    assert result.status is EvaluationStatus.ERROR
    assert result.error_code == "NoSensitivePortsConfigured"
