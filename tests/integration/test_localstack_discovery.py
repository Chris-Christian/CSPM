"""Real resource-discovery checks against loopback-only LocalStack."""

import json
from uuid import UUID, uuid4

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from cspm.aws.client_factory import create_client
from cspm.aws.connectivity import EndpointUnavailableError, verify_connectivity
from cspm.cli import main
from cspm.collectors import (
    DiscoveryEngine,
    EC2SecurityGroupCollector,
    IAMCollector,
    S3Collector,
)
from cspm.config import load_config
from cspm.models.enums import ScanStatus, TargetType
from cspm.persistence import ScanRepository


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


@pytest.mark.integration
def test_cli_scan_persists_findings_and_reports_localstack_results(
    localstack_resources, tmp_path
) -> None:
    resources = localstack_resources
    resources["ec2"].authorize_security_group_ingress(
        GroupId=resources["group_id"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "CSPM rule test"}],
            }
        ],
    )
    database = tmp_path / "end-to-end.sqlite3"

    scan_result = CliRunner().invoke(
        main, ["scan", "--database", str(database)]
    )

    assert scan_result.exit_code in {0, 2}, scan_result.output
    scan_id = UUID(scan_result.output.split("Scan ID: ", 1)[1].splitlines()[0])
    repository = ScanRepository(database)
    stored_scan = repository.get_scan(scan_id)
    assert stored_scan is not None
    assert stored_scan.status is ScanStatus.COMPLETED
    assert any(
        resource.resource_id == resources["bucket"]
        for resource in repository.get_resources(scan_id)
    )
    assert any(
        finding.rule_id == "EC2-001"
        and finding.resource_id == resources["group_id"]
        for finding in repository.get_findings(scan_id)
    )
    persisted_errors = repository.get_assessment_errors(scan_id)
    assert persisted_errors is not None

    report_dir = tmp_path / "reports"
    report_result = CliRunner().invoke(
        main,
        [
            "report",
            str(scan_id),
            "--database",
            str(database),
            "--output-dir",
            str(report_dir),
        ],
    )
    assert report_result.exit_code == 0, report_result.output

    scan_report_dir = report_dir / str(scan_id)
    json_report = json.loads(
        (scan_report_dir / "findings.json").read_text(encoding="utf-8")
    )
    html_report = (scan_report_dir / "report.html").read_text(encoding="utf-8")
    markdown_report = (scan_report_dir / "report.md").read_text(encoding="utf-8")
    expected_finding = next(
        finding
        for finding in repository.get_findings(scan_id)
        if finding.rule_id == "EC2-001"
        and finding.resource_id == resources["group_id"]
    )
    meaningful_finding_content = (
        "Security group exposes sensitive ports to IPv4 internet"
    )
    for report_content in (html_report, markdown_report):
        assert str(scan_id) in report_content
        assert str(expected_finding.finding_id) in report_content
        assert meaningful_finding_content in report_content
    assert json_report["assessment"]["errors"] is not None
    assert len(json_report["assessment"]["errors"]) == len(persisted_errors)
    assert len(json_report["findings"]) == len(repository.get_findings(scan_id))
    assert any(
        finding["rule_id"] == "EC2-001"
        and finding["resource_id"] == resources["group_id"]
        for finding in json_report["findings"]
    )

    original_json = (scan_report_dir / "findings.json").read_text(encoding="utf-8")
    overwrite_result = CliRunner().invoke(
        main,
        [
            "report",
            str(scan_id),
            "--database",
            str(database),
            "--output-dir",
            str(report_dir),
        ],
    )
    assert overwrite_result.exit_code == 1
    assert "never overwritten" in overwrite_result.output
    assert (scan_report_dir / "findings.json").read_text(encoding="utf-8") == (
        original_json
    )
