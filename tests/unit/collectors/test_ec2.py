from uuid import uuid4

from botocore.exceptions import ClientError

from cspm.collectors.ec2 import EC2SecurityGroupCollector
from cspm.models.enums import CollectorStatus


class FakeEC2:
    def __init__(self, responses=None):
        self.responses = list(responses or [{"SecurityGroups": []}])
        self.calls = []
        self.failure = None

    def describe_security_groups(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure:
            raise self.failure
        return self.responses.pop(0)


def test_ec2_empty_inventory_succeeds() -> None:
    outcome = EC2SecurityGroupCollector(client=FakeEC2()).collect(uuid4())

    assert outcome.resources == []
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_ec2_normalizes_ingress_egress_ipv4_ipv6_references_and_tags() -> None:
    group = {
        "GroupId": "sg-123",
        "GroupName": "demo",
        "Description": "unit test",
        "VpcId": "vpc-123",
        "OwnerId": "000000000000",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                "UserIdGroupPairs": [{"GroupId": "sg-peer"}],
            }
        ],
        "IpPermissionsEgress": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
        "Tags": [{"Key": "purpose", "Value": "test"}],
    }
    client = FakeEC2(
        [{"SecurityGroups": [group], "NextToken": "page-2"}, {"SecurityGroups": []}]
    )
    scan_id = uuid4()

    outcome = EC2SecurityGroupCollector(client=client).collect(scan_id)
    resource = outcome.resources[0]

    assert client.calls == [
        {"MaxResults": 1000},
        {"MaxResults": 1000, "NextToken": "page-2"},
    ]
    assert resource.resource_type == "security_group"
    assert resource.scan_id == scan_id
    assert resource.tags == {"purpose": "test"}
    assert resource.raw_metadata["ingress"][0]["Ipv6Ranges"][0]["CidrIpv6"] == "::/0"
    assert (
        resource.raw_metadata["ingress"][0]["UserIdGroupPairs"][0]["GroupId"]
        == "sg-peer"
    )
    assert resource.raw_metadata["egress"]
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_ec2_access_denied_fails_inventory() -> None:
    client = FakeEC2()
    client.failure = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "DescribeSecurityGroups"
    )

    outcome = EC2SecurityGroupCollector(client=client).collect(uuid4())

    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].error_code == "AccessDenied"


def test_ec2_preserves_first_page_resources_when_later_page_fails() -> None:
    class SecondPageFailure(FakeEC2):
        def describe_security_groups(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get("NextToken"):
                raise RuntimeError("later page unavailable")
            return self.responses.pop(0)

    client = SecondPageFailure(
        [
            {
                "SecurityGroups": [{"GroupId": "sg-123"}],
                "NextToken": "page-2",
            }
        ]
    )

    outcome = EC2SecurityGroupCollector(client=client).collect(uuid4())

    assert [resource.resource_id for resource in outcome.resources] == ["sg-123"]
    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].operation == "DescribeSecurityGroups"


def test_ec2_marks_missing_rule_arrays_as_partial_coverage() -> None:
    client = FakeEC2([{"SecurityGroups": [{"GroupId": "sg-123"}]}])

    outcome = EC2SecurityGroupCollector(client=client).collect(uuid4())

    assert outcome.resources[0].raw_metadata["ingress_status"] == "error"
    assert outcome.resources[0].raw_metadata["egress_status"] == "error"
    assert outcome.result.status is CollectorStatus.PARTIAL


def test_ec2_preserves_group_when_tag_normalization_fails() -> None:
    valid_group = {
        "GroupId": "sg-valid",
        "IpPermissions": [],
        "IpPermissionsEgress": [],
        "Tags": [{"Key": "environment", "Value": "test"}],
    }
    malformed_group = {
        "GroupId": "sg-invalid-tags",
        "GroupName": "preserve-this-resource",
        "IpPermissions": [],
        "IpPermissionsEgress": [],
        "Tags": [{"Key": "environment", "Value": 17}],
    }
    client = FakeEC2(
        [{"SecurityGroups": [valid_group, malformed_group]}]
    )

    outcome = EC2SecurityGroupCollector(client=client).collect(uuid4())
    resources_by_id = {item.resource_id: item for item in outcome.resources}
    invalid_tags_resource = resources_by_id["sg-invalid-tags"]

    assert resources_by_id["sg-valid"].tags == {"environment": "test"}
    assert "tags_status" not in resources_by_id["sg-valid"].raw_metadata
    assert invalid_tags_resource.raw_metadata["GroupName"] == "preserve-this-resource"
    assert invalid_tags_resource.tags == {}
    assert invalid_tags_resource.raw_metadata["tags_status"] == "failed"
    assert invalid_tags_resource.raw_metadata["unvalidated_tags"] == malformed_group[
        "Tags"
    ]
    assert outcome.result.status is CollectorStatus.PARTIAL
    assert len(outcome.result.errors) == 1
    assert outcome.result.errors[0].operation == "NormalizeSecurityGroupTags"
