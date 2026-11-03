"""Tests for S3 public-access detection and evidence handling."""

from uuid import uuid4

import pytest

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.rules import AssessmentEngine, EvaluationStatus
from cspm.rules.s3 import (
    S3PublicAccessBlockRule,
    S3PublicAclRule,
    S3PublicPolicyRule,
)

_ALL_FLAGS_ENABLED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def make_bucket(**metadata: object) -> Resource:
    raw_metadata: dict[str, object] = {
        "policy": {"status": "present", "document": {"Statement": []}},
        "policy_status": {"status": "present", "is_public": False},
        "acl": {"Grants": []},
        "public_access_block": {
            "status": "present",
            "configuration": dict(_ALL_FLAGS_ENABLED),
        },
    }
    raw_metadata.update(metadata)
    return Resource(
        scan_id=uuid4(),
        resource_id="bucket-a",
        resource_type="s3_bucket",
        region="us-east-1",
        raw_metadata=raw_metadata,
    )


def test_public_policy_is_finding_when_restrict_public_buckets_is_off() -> None:
    resource = make_bucket(
        policy_status={"status": "present", "is_public": True},
        public_access_block={
            "status": "present",
            "configuration": {
                **_ALL_FLAGS_ENABLED,
                "RestrictPublicBuckets": False,
            },
        },
    )

    result = S3PublicPolicyRule().evaluate(resource)

    assert result.status is EvaluationStatus.FINDING
    assert result.evidence["policy_status"]["is_public"] is True
    assert result.evidence["public_access_block"]["BlockPublicPolicy"] is True


def test_public_policy_blocked_by_restrict_public_buckets_is_not_exposed() -> None:
    resource = make_bucket(
        policy_status={"status": "present", "is_public": True}
    )

    result = S3PublicPolicyRule().evaluate(resource)

    assert result.status is EvaluationStatus.PASSED
    assert result.detail_code == "BlockedByRestrictPublicBuckets"


def test_non_public_policy_passes_and_absent_policy_is_known() -> None:
    assert (
        S3PublicPolicyRule().evaluate(make_bucket()).status
        is EvaluationStatus.PASSED
    )
    absent = make_bucket(
        policy={"status": "absent"}, policy_status={"status": "absent"}
    )

    assert S3PublicPolicyRule().evaluate(absent).detail_code == "NoBucketPolicy"


def test_missing_or_invalid_policy_evidence_is_an_error() -> None:
    missing = make_bucket()
    del missing.raw_metadata["policy_status"]
    invalid = make_bucket(
        policy={"status": "invalid", "parse_status": "invalid_json"},
        policy_status={"status": "present", "is_public": False},
    )

    assert S3PublicPolicyRule().evaluate(missing).status is EvaluationStatus.ERROR
    assert S3PublicPolicyRule().evaluate(invalid).status is EvaluationStatus.ERROR


def test_public_acl_grants_are_findings_unless_ignored() -> None:
    public_acl = {
        "Grants": [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }
        ]
    }
    exposed = make_bucket(
        acl=public_acl,
        public_access_block={
            "status": "present",
            "configuration": {**_ALL_FLAGS_ENABLED, "IgnorePublicAcls": False},
        },
    )
    ignored = make_bucket(acl=public_acl)

    finding = S3PublicAclRule().evaluate(exposed)
    passed = S3PublicAclRule().evaluate(ignored)

    assert finding.status is EvaluationStatus.FINDING
    assert finding.evidence["public_grants"] == [
        {"group": "AllUsers", "permission": "READ"}
    ]
    assert passed.status is EvaluationStatus.PASSED
    assert passed.detail_code == "IgnoredByIgnorePublicAcls"


def test_block_public_acls_alone_does_not_hide_existing_public_acl() -> None:
    resource = make_bucket(
        acl={
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    },
                    "Permission": "FULL_CONTROL",
                }
            ]
        },
        public_access_block={
            "status": "present",
            "configuration": {
                **_ALL_FLAGS_ENABLED,
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
            },
        },
    )

    assert S3PublicAclRule().evaluate(resource).status is EvaluationStatus.FINDING


def test_malformed_acl_is_an_evaluation_error() -> None:
    for acl in ({"status": "error"}, {"Grants": [None]}, {"Grants": "bad"}):
        result = S3PublicAclRule().evaluate(make_bucket(acl=acl))
        assert result.status is EvaluationStatus.ERROR


@pytest.mark.parametrize("reverse", [False, True])
def test_confirmed_public_acl_finding_survives_malformed_grant(reverse: bool) -> None:
    public_grant = {
        "Grantee": {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
        },
        "Permission": "READ",
    }
    grants: list[object] = [public_grant, None]
    if reverse:
        grants.reverse()
    bucket = make_bucket(
        acl={"Grants": grants},
        public_access_block={
            "status": "present",
            "configuration": {**_ALL_FLAGS_ENABLED, "IgnorePublicAcls": False},
        },
    )

    result = AssessmentEngine(rules=[S3PublicAclRule()]).evaluate([bucket])

    assert len(result.findings) == 1
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "InvalidAclGrant"
    assert result.errors[0].finding == result.findings[0]
    assert result.is_complete is False


def test_bucket_level_pab_rule_distinguishes_enabled_absent_and_missing() -> None:
    enabled = S3PublicAccessBlockRule().evaluate(make_bucket())
    partial = S3PublicAccessBlockRule().evaluate(
        make_bucket(
            public_access_block={
                "status": "present",
                "configuration": {**_ALL_FLAGS_ENABLED, "IgnorePublicAcls": False},
            }
        )
    )
    absent = S3PublicAccessBlockRule().evaluate(
        make_bucket(public_access_block={"status": "absent"})
    )
    no_evidence = make_bucket()
    del no_evidence.raw_metadata["public_access_block"]

    assert enabled.status is EvaluationStatus.PASSED
    assert enabled.detail_code == "AllBucketLevelPabFlagsEnabled"
    assert partial.status is EvaluationStatus.FINDING
    assert partial.evidence["current_public_exposure_confirmed"] is False
    assert absent.status is EvaluationStatus.FINDING
    assert (
        S3PublicAccessBlockRule().evaluate(no_evidence).status
        is EvaluationStatus.ERROR
    )


def test_rules_reject_resources_of_other_types() -> None:
    with pytest.raises(ValueError, match="resource type"):
        S3PublicPolicyRule().evaluate(
            Resource(
                scan_id=uuid4(),
                resource_id="role",
                resource_type="iam_role",
                region="global",
            )
        )


def test_s3_rule_metadata_has_no_unverified_cis_mapping() -> None:
    for rule in (S3PublicPolicyRule(), S3PublicAclRule(), S3PublicAccessBlockRule()):
        assert rule.severity in {Severity.HIGH, Severity.MEDIUM}
        assert rule.cis_control is None
        assert rule.cis_version is None
