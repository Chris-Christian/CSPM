"""Real resource-discovery checks against loopback-only LocalStack."""

import json
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from cspm.aws.client_factory import create_client
from cspm.aws.connectivity import EndpointUnavailableError, verify_connectivity
from cspm.collectors import (
    DiscoveryEngine,
    EC2SecurityGroupCollector,
    IAMCollector,
    S3Collector,
)
from cspm.config import load_config
from cspm.models.enums import TargetType


def _require_localstack():
    config = load_config()
    if config.target is not TargetType.LOCALSTACK:
        pytest.fail(
            "Set CSPM_TARGET=localstack; integration tests never connect to AWS"
        )
    host = config.localstack_endpoint_url.host.strip("[]")
    if host not in {"localhost", "127.0.0.1", "::1"}:
        pytest.fail("Integration tests only connect to a loopback LocalStack endpoint")
    try:
        verify_connectivity(config)
    except EndpointUnavailableError as exc:
        pytest.skip(f"LocalStack endpoint is unavailable: {exc}")
    return config


@pytest.fixture
def localstack_resources():
    """Create and reliably clean up only this fixture's uniquely named resources."""
    config = _require_localstack()
    s3 = create_client("s3", config)
    iam = create_client("iam", config)
    ec2 = create_client("ec2", config)
    suffix = uuid4().hex[:12]
    bucket = f"cspm-it-{suffix}"
    role_name = f"cspm-integration-{suffix}"
    group_name = f"cspm-it-{suffix}"
    created_bucket = False
    created_role = False
    group_id = None

    try:
        try:
            s3.create_bucket(Bucket=bucket)
            created_bucket = True
            s3.put_bucket_tagging(
                Bucket=bucket,
                Tagging={"TagSet": [{"Key": "cspm-test", "Value": "integration"}]},
            )
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            s3.put_bucket_policy(
                Bucket=bucket,
                Policy=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": f"arn:aws:s3:::{bucket}/*",
                                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                            }
                        ],
                    }
                ),
            )

            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                ),
                Tags=[{"Key": "cspm-test", "Value": "integration"}],
            )
            created_role = True
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="cspm-inline-test",
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:ListBucket",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            )

            groups = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"]
            vpc_id = groups[0]["VpcId"] if groups else None
            create_args = {
                "GroupName": group_name,
                "Description": "CSPM integration test group",
            }
            if vpc_id:
                create_args["VpcId"] = vpc_id
            group_id = ec2.create_security_group(**create_args)["GroupId"]
            ec2.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "198.51.100.0/24", "Description": "CSPM test"}
                        ],
                    }
                ],
            )
            ec2.create_tags(
                Resources=[group_id],
                Tags=[{"Key": "cspm-test", "Value": "integration"}],
            )
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "service error")
            pytest.fail(
                "LocalStack is reachable but an integration service/API failed "
                f"({error_code}); "
                "enable S3, IAM, and EC2 in docker-compose.yml."
            )

        yield {
            "config": config,
            "s3": s3,
            "iam": iam,
            "ec2": ec2,
            "bucket": bucket,
            "role": role_name,
            "group_id": group_id,
        }
    finally:
        cleanup_errors = []
        if group_id:
            try:
                ec2.delete_security_group(GroupId=group_id)
            except Exception as exc:
                cleanup_errors.append(f"DeleteSecurityGroup ({type(exc).__name__})")
        if created_role:
            try:
                iam.delete_role_policy(
                    RoleName=role_name, PolicyName="cspm-inline-test"
                )
            except Exception as exc:
                cleanup_errors.append(f"DeleteRolePolicy ({type(exc).__name__})")
            try:
                iam.delete_role(RoleName=role_name)
            except Exception as exc:
                cleanup_errors.append(f"DeleteRole ({type(exc).__name__})")
        if created_bucket:
            try:
                s3.delete_bucket_policy(Bucket=bucket)
            except Exception as exc:
                cleanup_errors.append(f"DeleteBucketPolicy ({type(exc).__name__})")
            try:
                s3.delete_public_access_block(Bucket=bucket)
            except Exception as exc:
                cleanup_errors.append(f"DeletePublicAccessBlock ({type(exc).__name__})")
            try:
                s3.delete_bucket(Bucket=bucket)
            except Exception as exc:
                cleanup_errors.append(f"DeleteBucket ({type(exc).__name__})")
        if cleanup_errors:
            pytest.fail(
                "LocalStack fixture cleanup failed: " + ", ".join(cleanup_errors)
            )


@pytest.mark.integration
def test_real_collectors_discover_s3_iam_and_ec2(localstack_resources) -> None:
    resources = localstack_resources
    scan_id = uuid4()
    engine = DiscoveryEngine(
        config=resources["config"],
        collectors=[
            S3Collector(resources["config"], resources["s3"]),
            IAMCollector(resources["config"], resources["iam"]),
            EC2SecurityGroupCollector(resources["config"], resources["ec2"]),
        ],
    )

    result = engine.discover(scan_id)
    assert all(item.status.value == "success" for item in result.collector_results), [
        (item.collector_name, item.status.value, item.errors)
        for item in result.collector_results
    ]
    by_identity = {
        (item.resource_type, item.resource_id): item for item in result.resources
    }

    bucket = by_identity[("s3_bucket", resources["bucket"])]
    assert bucket.scan_id == scan_id
    assert bucket.tags["cspm-test"] == "integration"
    assert bucket.raw_metadata["public_access_block"]["configuration"][
        "BlockPublicAcls"
    ]
    assert bucket.raw_metadata["policy"]["status"] == "present"
    assert bucket.raw_metadata["policy_status"]["is_public"] is False

    role = next(
        item
        for item in result.resources
        if item.resource_type == "iam_role"
        and item.raw_metadata.get("RoleName") == resources["role"]
    )
    assert role.tags["cspm-test"] == "integration"
    assert role.raw_metadata["inline_policies"]
    inline_id = role.raw_metadata["inline_policies"][0]
    assert by_identity[("iam_policy", inline_id)].raw_metadata["policy_document"]

    group = by_identity[("security_group", resources["group_id"])]
    assert group.raw_metadata["ingress"]
    assert group.tags["cspm-test"] == "integration"
