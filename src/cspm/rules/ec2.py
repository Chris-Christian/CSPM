"""Rules for IPv4 and IPv6 security-group ingress on sensitive ports."""

from collections.abc import Mapping
from ipaddress import collapse_addresses, ip_network
from typing import Any

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.models.rule import Rule
from cspm.rules.base import BaseRule, RuleEvaluation


class EC2SensitiveIpv4IngressRule(BaseRule):
    """Find 0.0.0.0/0 ingress overlapping configured sensitive ports."""

    definition = Rule(
        rule_id="EC2-001",
        title="Security group exposes sensitive ports to IPv4 internet",
        resource_type="security_group",
        severity=Severity.HIGH,
        remediation_text=(
            "Restrict security-group ingress to trusted source CIDRs and only the "
            "ports required by the workload."
        ),
    )

    def __init__(
        self,
        sensitive_tcp_ports: tuple[int, ...],
        sensitive_udp_ports: tuple[int, ...] = (),
    ) -> None:
        self.sensitive_tcp_ports = frozenset(sensitive_tcp_ports)
        self.sensitive_udp_ports = frozenset(sensitive_udp_ports)

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        return _evaluate_ingress(
            self, resource, 4, self.sensitive_tcp_ports, self.sensitive_udp_ports
        )


class EC2SensitiveIpv6IngressRule(BaseRule):
    """Find ::/0 ingress separately from the IPv4 security-group check."""

    definition = Rule(
        rule_id="EC2-002",
        title="Security group exposes sensitive ports to IPv6 internet",
        resource_type="security_group",
        severity=Severity.HIGH,
        remediation_text=(
            "Restrict IPv6 security-group ingress to trusted source ranges and only "
            "the ports required by the workload."
        ),
    )

    def __init__(
        self,
        sensitive_tcp_ports: tuple[int, ...],
        sensitive_udp_ports: tuple[int, ...] = (),
    ) -> None:
        self.sensitive_tcp_ports = frozenset(sensitive_tcp_ports)
        self.sensitive_udp_ports = frozenset(sensitive_udp_ports)

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        return _evaluate_ingress(
            self, resource, 6, self.sensitive_tcp_ports, self.sensitive_udp_ports
        )


def _evaluate_ingress(
    rule: BaseRule,
    resource: Resource,
    address_family: int,
    tcp_ports: frozenset[int],
    udp_ports: frozenset[int],
) -> RuleEvaluation:
    rule.require_resource_type(resource)
    configured_ports = tcp_ports | udp_ports
    if not configured_ports:
        return RuleEvaluation.error("NoSensitivePortsConfigured")
    metadata = resource.raw_metadata
    if metadata.get("ingress_status") is not None:
        return RuleEvaluation.error("IngressEvidenceUnavailable")
    permissions = metadata.get("ingress")
    if not isinstance(permissions, list):
        return RuleEvaluation.error("MissingIngressEvidence")

    exposures: list[dict[str, Any]] = []
    errors: list[str] = []
    range_key = "IpRanges" if address_family == 4 else "Ipv6Ranges"
    cidr_key = "CidrIp" if address_family == 4 else "CidrIpv6"
    for permission in permissions:
        if not isinstance(permission, Mapping):
            errors.append("InvalidIngressPermission")
            continue
        protocol = permission.get("IpProtocol")
        if not isinstance(protocol, str) or not protocol:
            errors.append("InvalidIngressProtocol")
            continue
        normalized_protocol = {"6": "tcp", "17": "udp"}.get(protocol, protocol.lower())
        if normalized_protocol == "-1":
            applicable_ports = configured_ports
            start_port = end_port = None
        elif normalized_protocol in {"tcp", "udp"}:
            applicable_ports = tcp_ports if normalized_protocol == "tcp" else udp_ports
            start_port, end_port = _port_range(permission)
            if start_port is None:
                errors.append("InvalidIngressPortRange")
                continue
        else:
            applicable_ports = frozenset()
            start_port = end_port = None

        ranges = permission.get(range_key, [])
        if not isinstance(ranges, list):
            errors.append("InvalidIngressRanges")
            continue
        if not applicable_ports:
            continue
        networks = []
        for ip_range in ranges:
            if not isinstance(ip_range, Mapping):
                errors.append("InvalidIngressRange")
                continue
            cidr = ip_range.get(cidr_key)
            if not isinstance(cidr, str):
                errors.append("InvalidIngressCidr")
                continue
            try:
                network = ip_network(cidr, strict=False)
            except ValueError:
                errors.append("InvalidIngressCidr")
                continue
            if network.version == address_family:
                networks.append(network)

        # Collapse first so 0.0.0.0/1 + 128.0.0.0/1 is seen as 0.0.0.0/0.
        sources = sorted({str(network) for network in networks})
        for network in collapse_addresses(networks):
            if network.prefixlen != 0:
                continue
            if normalized_protocol == "-1":
                matched_ports = sorted(configured_ports)
            else:
                assert start_port is not None and end_port is not None
                matched_ports = sorted(
                    port for port in applicable_ports if start_port <= port <= end_port
                )
            if matched_ports:
                exposure: dict[str, Any] = {
                    "protocol": normalized_protocol,
                    "cidr": str(network),
                    "from_port": start_port,
                    "to_port": end_port,
                    "sensitive_ports": matched_ports[:20],
                    "omitted_sensitive_port_count": max(0, len(matched_ports) - 20),
                }
                if sources != [str(network)]:
                    exposure["source_cidrs"] = sources[:20]
                exposures.append(exposure)

    unique_errors = tuple(dict.fromkeys(errors))
    if exposures:
        return RuleEvaluation.finding(
            {
                "address_family": "IPv4" if address_family == 4 else "IPv6",
                "exposures": exposures[:20],
                "omitted_exposure_count": max(0, len(exposures) - 20),
            },
            error_codes=unique_errors,
        )
    if unique_errors:
        return RuleEvaluation.error(
            unique_errors[0], other_error_codes=unique_errors[1:]
        )
    return RuleEvaluation.passed("NoInternetIngressOnConfiguredSensitivePorts")


def _port_range(
    permission: Mapping[str, object],
) -> tuple[int | None, int | None]:
    """Read and validate an inclusive TCP/UDP port range."""
    start, end = permission.get("FromPort"), permission.get("ToPort")
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
        return None, None
    return start, end
