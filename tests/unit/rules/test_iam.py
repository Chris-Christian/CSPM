"""Tests for IAM wildcard permission and role trust rules."""

from uuid import uuid4

import pytest

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.rules import AssessmentEngine, EvaluationStatus
from cspm.rules.iam import IamWildcardPermissionRule, IamWildcardTrustRule


def make_policy(document: object = None, **metadata: object) -> Resource:
    raw_metadata = {"policy_document": document}
    raw_metadata.update(metadata)
    return Resource(
        scan_id=uuid4(),
        resource_id="arn:aws:iam::111122223333:policy/demo",
        resource_type="iam_policy",
        region="global",
        raw_metadata=raw_metadata,
    )


def make_role(document: object = None, **metadata: object) -> Resource:
    raw_metadata = {"assume_role_trust_policy": document}
    raw_metadata.update(metadata)
    return Resource(
        scan_id=uuid4(),
        resource_id="arn:aws:iam::111122223333:role/demo",
        resource_type="iam_role",
        region="global",
        raw_metadata=raw_metadata,
    )


@pytest.mark.parametrize(
    "action",
    ["*", "s3:*"],
    ids=["all-actions", "service-wildcard"],
)
def test_allow_action_wildcards_create_findings(action: str) -> None:
    resource = make_policy(
        {"Statement": {"Effect": "Allow", "Action": action, "Resource": "*"}},
        owner_role_name="inline-owner",
    )

    result = IamWildcardPermissionRule().evaluate(resource)

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["policy_source"] == "inline"
    assert "WildcardAction" in result.evidence["statements"][0]["reasons"]
    assert result.evidence["statements"][0]["wildcard_resource"] is True


def test_managed_policy_wildcard_evidence_is_bounded_and_identified() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(
            {
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
                ]
            }
        )
    )

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["policy_source"] == "managed"
    assert result.evidence["statements"] == [
        {
            "statement_index": 1,
            "reasons": ["WildcardAction", "WildcardResourceWithWildcardAction"],
            "actions": ["iam:*"],
            "omitted_action_count": 0,
            "wildcard_resource": True,
        }
    ]


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Allow", "NotAction": "iam:ListUsers", "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:one"},
    ],
)
def test_allow_not_action_and_not_resource_are_broad_findings(statement: dict) -> None:
    result = IamWildcardPermissionRule().evaluate(make_policy({"Statement": statement}))

    assert result.status is EvaluationStatus.FINDING


def test_wildcard_resource_alone_with_scoped_action_is_not_overprivileged() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            }
        )
    )

    assert result.status is EvaluationStatus.PASSED


def test_partial_action_family_wildcard_is_not_labeled_overprivileged() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "ec2:Describe*",
                    "Resource": "*",
                }
            }
        )
    )

    assert result.status is EvaluationStatus.PASSED


def test_deny_wildcards_do_not_trigger_and_scoped_allows_pass() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(
            {
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "arn:aws:s3:::specific-bucket/*",
                    },
                ]
            }
        )
    )

    assert result.status is EvaluationStatus.PASSED


def test_conditional_wildcard_permissions_are_incomplete() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            }
        )
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.error_code == "ConditionalBroadPermissionUnsupported"


@pytest.mark.parametrize("reverse", [False, True])
def test_confirmed_permission_finding_survives_other_incomplete_statement(
    reverse: bool,
) -> None:
    confirmed = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    unsupported = {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    }
    statements = [confirmed, unsupported]
    if reverse:
        statements.reverse()

    result = AssessmentEngine(rules=[IamWildcardPermissionRule()]).evaluate(
        [make_policy({"Statement": statements})]
    )

    assert len(result.findings) == 1
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "ConditionalBroadPermissionUnsupported"
    assert result.errors[0].finding == result.findings[0]
    assert result.is_complete is False


@pytest.mark.parametrize(
    "document",
    [None, {}, {"Statement": "not-a-statement"}, {"Statement": [None]}],
)
def test_missing_or_malformed_policy_documents_are_errors(document: object) -> None:
    result = IamWildcardPermissionRule().evaluate(make_policy(document))

    assert result.status is EvaluationStatus.ERROR


def test_policy_document_enrichment_error_is_not_a_pass() -> None:
    result = IamWildcardPermissionRule().evaluate(
        make_policy(policy_document_status="error")
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.error_code == "PolicyDocumentUnavailable"


def test_wildcard_trust_principal_finding_and_deny_pass() -> None:
    document = {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        ]
    }

    result = IamWildcardTrustRule().evaluate(make_role(document))

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["statements"] == [
        {
            "statement_index": 1,
            "wildcard_principal_fields": ["AWS"],
            "actions": ["sts:AssumeRole"],
        }
    ]


def test_scoped_and_conditional_trust_policies_are_not_false_findings() -> None:
    scoped = IamWildcardTrustRule().evaluate(
        make_role(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                }
            }
        )
    )
    conditional = IamWildcardTrustRule().evaluate(
        make_role(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
                }
            }
        )
    )

    assert scoped.status is EvaluationStatus.PASSED
    assert conditional.status is EvaluationStatus.ERROR
    assert conditional.error_code == "ConditionalTrustPolicyUnsupported"


def test_missing_trust_evidence_is_an_error_and_cis_is_unset() -> None:
    rule = IamWildcardTrustRule()

    assert rule.evaluate(make_role()).status is EvaluationStatus.ERROR
    assert rule.severity is Severity.CRITICAL
    assert rule.cis_control is None
    assert rule.cis_version is None
