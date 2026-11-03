from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from cspm.collectors.iam import IAMCollector
from cspm.models.enums import CollectorStatus

POLICY_ARN = "arn:aws:iam::000000000000:policy/demo"


class FakeIAM:
    def __init__(self):
        self.calls = []
        self.failures = {}

    def call(self, name, response, **kwargs):
        self.calls.append((name, kwargs))
        if name in self.failures:
            raise self.failures[name]
        return response

    def list_roles(self, **kwargs):
        if kwargs.get("Marker") == "page-2":
            return self.call("list_roles", {"Roles": []}, **kwargs)
        response = getattr(self, "roles", {"Roles": []})
        if getattr(self, "role_pagination", False):
            response = {
                "Roles": [
                    {
                        "RoleName": "demo",
                        "Arn": "arn:aws:iam::000000000000:role/demo",
                        "AssumeRolePolicyDocument": {"Statement": []},
                        "Tags": [{"Key": "team", "Value": "security"}],
                    }
                ],
                "IsTruncated": True,
                "Marker": "page-2",
            }
        return self.call("list_roles", response, **kwargs)

    def list_policies(self, **kwargs):
        return self.call(
            "list_policies", getattr(self, "policies", {"Policies": []}), **kwargs
        )

    def list_attached_role_policies(self, **kwargs):
        return self.call(
            "list_attached_role_policies",
            {"AttachedPolicies": getattr(self, "attached_policies", [])},
            **kwargs,
        )

    def list_role_policies(self, **kwargs):
        return self.call(
            "list_role_policies",
            {"PolicyNames": getattr(self, "inline_names", [])},
            **kwargs,
        )

    def list_role_tags(self, **kwargs):
        marker = kwargs.get("Marker")
        pages = getattr(self, "role_tag_pages", None)
        if pages is not None:
            response = pages.get(marker, {"Tags": []})
        else:
            response = {"Tags": getattr(self, "role_tags", [])}
        return self.call("list_role_tags", response, **kwargs)

    def get_role_policy(self, **kwargs):
        return self.call(
            "get_role_policy",
            {"PolicyDocument": {"Statement": [{"Effect": "Allow"}]}},
            **kwargs,
        )

    def get_policy(self, **kwargs):
        return self.call(
            "get_policy",
            {
                "Policy": {
                    "Arn": kwargs["PolicyArn"],
                    "PolicyName": "demo",
                    "Path": "/",
                    "DefaultVersionId": "v1",
                    "Tags": [{"Key": "owner", "Value": "security"}],
                }
            },
            **kwargs,
        )

    def get_policy_version(self, **kwargs):
        return self.call(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": {"Statement": [{"Action": "s3:GetObject"}]}
                }
            },
            **kwargs,
        )


def test_iam_empty_inventory_succeeds() -> None:
    outcome = IAMCollector(client=FakeIAM()).collect(uuid4())

    assert outcome.resources == []
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_iam_discovers_role_inline_policy_and_managed_policy_once() -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
                "Path": "/",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Principal": {"Service": "ec2.amazonaws.com"}}]
                },
            }
        ]
    }
    client.role_tags = [{"Key": "team", "Value": "security"}]
    client.policies = {
        "Policies": [
            {"Arn": POLICY_ARN, "PolicyName": "demo", "DefaultVersionId": "v1"}
        ]
    }
    client.attached_policies = [{"PolicyName": "demo", "PolicyArn": POLICY_ARN}]
    client.inline_names = ["inline/demo"]
    scan_id = uuid4()

    outcome = IAMCollector(client=client).collect(scan_id)
    by_id = {resource.resource_id: resource for resource in outcome.resources}

    role = by_id["arn:aws:iam::000000000000:role/demo"]
    assert role.resource_type == "iam_role"
    assert role.region == "global"
    assert role.scan_id == scan_id
    assert role.tags == {"team": "security"}
    assert ("list_role_tags", {"RoleName": "demo"}) in client.calls
    assert role.raw_metadata["AssumeRolePolicyDocument"]["Statement"]
    assert role.raw_metadata["attached_managed_policies"][0]["PolicyArn"] == POLICY_ARN
    assert role.raw_metadata["inline_policies"] == [
        "arn:aws:iam::000000000000:role/demo/inline/inline%2Fdemo"
    ]
    assert by_id[POLICY_ARN].raw_metadata["policy_document"]["Statement"]
    assert by_id[POLICY_ARN].raw_metadata["attached_to_roles"] == ["demo"]
    assert (
        len(
            [
                resource
                for resource in outcome.resources
                if resource.resource_id == POLICY_ARN
            ]
        )
        == 1
    )
    assert outcome.result.status is CollectorStatus.SUCCESS
    assert not {name for name, _ in client.calls} & {
        "put_role_policy",
        "attach_role_policy",
        "create_policy",
    }


def test_iam_reads_all_pages_and_discovers_attached_aws_managed_policy() -> None:
    client = FakeIAM()
    client.role_pagination = True
    client.attached_policies = [
        {
            "PolicyName": "ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        }
    ]

    outcome = IAMCollector(client=client).collect(uuid4())

    assert client.calls[1] == ("list_roles", {"Marker": "page-2"})
    assert any(
        resource.resource_id.endswith("ReadOnlyAccess")
        for resource in outcome.resources
    )
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_iam_role_without_tags_has_empty_tags_and_succeeds() -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
                "AssumeRolePolicyDocument": {"Statement": []},
            }
        ]
    }

    outcome = IAMCollector(client=client).collect(uuid4())

    role = next(
        resource
        for resource in outcome.resources
        if resource.resource_type == "iam_role"
    )
    assert role.tags == {}
    assert "tags_status" not in role.raw_metadata
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_iam_role_tags_are_collected_from_all_pages() -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
                "AssumeRolePolicyDocument": {"Statement": []},
            }
        ]
    }
    client.role_tag_pages = {
        None: {
            "Tags": [{"Key": "team", "Value": "security"}],
            "IsTruncated": True,
            "Marker": "tag-page-2",
        },
        "tag-page-2": {
            "Tags": [{"Key": "environment", "Value": "test"}],
            "IsTruncated": False,
        },
    }

    outcome = IAMCollector(client=client).collect(uuid4())

    role = next(
        resource
        for resource in outcome.resources
        if resource.resource_type == "iam_role"
    )
    assert role.tags == {"team": "security", "environment": "test"}
    assert [call for call in client.calls if call[0] == "list_role_tags"] == [
        ("list_role_tags", {"RoleName": "demo"}),
        ("list_role_tags", {"RoleName": "demo", "Marker": "tag-page-2"}),
    ]
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_iam_role_tag_enrichment_failure_preserves_role_and_reports_partial() -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
                "AssumeRolePolicyDocument": {"Statement": []},
            }
        ]
    }
    client.failures["list_role_tags"] = RuntimeError("sensitive service detail")

    outcome = IAMCollector(client=client).collect(uuid4())

    role = next(
        resource
        for resource in outcome.resources
        if resource.resource_type == "iam_role"
    )
    assert role.tags == {}
    assert role.raw_metadata["tags_status"] == "failed"
    assert outcome.result.status is CollectorStatus.PARTIAL
    error = next(
        error for error in outcome.result.errors if error.operation == "ListRoleTags"
    )
    assert "sensitive service detail" not in error.message


@pytest.mark.parametrize(
    "pages",
    [
        {None: {"Tags": [], "IsTruncated": True}},
        {
            None: {"Tags": [], "IsTruncated": True, "Marker": "same"},
            "same": {"Tags": [], "IsTruncated": True, "Marker": "same"},
        },
    ],
    ids=["missing-marker", "repeated-marker"],
)
def test_iam_role_tag_pagination_errors_do_not_report_success(pages) -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
                "AssumeRolePolicyDocument": {"Statement": []},
            }
        ]
    }
    client.role_tag_pages = pages

    outcome = IAMCollector(client=client).collect(uuid4())

    role = next(
        resource
        for resource in outcome.resources
        if resource.resource_type == "iam_role"
    )
    assert role.tags == {}
    assert role.raw_metadata["tags_status"] == "failed"
    assert outcome.result.status is CollectorStatus.PARTIAL
    assert any(error.operation == "ListRoleTags" for error in outcome.result.errors)


def test_iam_inventory_failure_is_failed_and_role_enrichment_failure_is_partial() -> (
    None
):
    failed_client = FakeIAM()
    failed_client.failures["list_roles"] = RuntimeError("inventory")
    assert (
        IAMCollector(client=failed_client).collect(uuid4()).result.status
        is CollectorStatus.FAILED
    )

    client = FakeIAM()
    client.roles = {
        "Roles": [{"RoleName": "demo", "Arn": "arn:aws:iam::000000000000:role/demo"}]
    }
    client.failures["list_role_policies"] = RuntimeError("incomplete")
    outcome = IAMCollector(client=client).collect(uuid4())
    assert len(outcome.resources) == 1
    assert outcome.result.status is CollectorStatus.PARTIAL
    assert "inline_policies_status" in outcome.resources[0].raw_metadata


def test_iam_policy_inventory_failure_preserves_discovered_roles_as_failed() -> None:
    client = FakeIAM()
    client.roles = {
        "Roles": [
            {
                "RoleName": "demo",
                "Arn": "arn:aws:iam::000000000000:role/demo",
            }
        ]
    }
    client.failures["list_policies"] = RuntimeError("policy inventory unavailable")

    outcome = IAMCollector(client=client).collect(uuid4())

    assert [resource.resource_type for resource in outcome.resources] == ["iam_role"]
    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].operation == "ListPolicies"


def test_iam_access_denied_on_role_inventory_is_failed() -> None:
    client = FakeIAM()
    client.failures["list_roles"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive detail"}},
        "ListRoles",
    )

    outcome = IAMCollector(client=client).collect(uuid4())

    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].error_code == "AccessDenied"
    assert "sensitive detail" not in outcome.result.errors[0].message
