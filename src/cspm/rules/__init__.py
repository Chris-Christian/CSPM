"""Extensible, read-only CSPM rule catalogue."""

from cspm.config import CSPMConfig
from cspm.rules.base import BaseRule, EvaluationStatus, RuleEvaluation
from cspm.rules.ec2 import EC2SensitiveIpv4IngressRule, EC2SensitiveIpv6IngressRule
from cspm.rules.engine import AssessmentEngine, AssessmentResult, EvaluationRecord
from cspm.rules.iam import IamWildcardPermissionRule, IamWildcardTrustRule
from cspm.rules.s3 import (
    S3PublicAccessBlockRule,
    S3PublicAclRule,
    S3PublicPolicyRule,
)


def built_in_rules(config: CSPMConfig) -> tuple[BaseRule, ...]:
    """Construct the explicit built-in catalogue for one validated config."""
    return (
        S3PublicPolicyRule(),
        S3PublicAclRule(),
        S3PublicAccessBlockRule(),
        IamWildcardPermissionRule(),
        IamWildcardTrustRule(),
        EC2SensitiveIpv4IngressRule(
            config.sensitive_ports, config.sensitive_udp_ports
        ),
        EC2SensitiveIpv6IngressRule(
            config.sensitive_ports, config.sensitive_udp_ports
        ),
    )


__all__ = [
    "AssessmentEngine",
    "AssessmentResult",
    "BaseRule",
    "EC2SensitiveIpv4IngressRule",
    "EC2SensitiveIpv6IngressRule",
    "EvaluationRecord",
    "EvaluationStatus",
    "IamWildcardPermissionRule",
    "IamWildcardTrustRule",
    "RuleEvaluation",
    "S3PublicAclRule",
    "S3PublicAccessBlockRule",
    "S3PublicPolicyRule",
    "built_in_rules",
]
