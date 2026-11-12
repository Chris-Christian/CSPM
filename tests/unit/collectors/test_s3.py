from datetime import UTC, datetime
from uuid import uuid4

from botocore.exceptions import ClientError

from cspm.collectors import s3 as s3_module
from cspm.collectors.s3 import S3Collector
from cspm.config import load_config
from cspm.models.enums import CollectorStatus


class FakeS3:
    def __init__(self, pages=None):
        self.pages = list(pages or [{"Buckets": []}])
        self.calls = []
        self.failures = {}

    def _call(self, name, response=None, **kwargs):
        self.calls.append((name, kwargs))
        if name in self.failures:
            raise self.failures[name]
        return response

    def list_buckets(self, **kwargs):
        return self._call("list_buckets", self.pages.pop(0), **kwargs)

    def get_bucket_location(self, **kwargs):
        return self._call(
            "get_bucket_location",
            getattr(self, "location", {"LocationConstraint": None}),
            **kwargs,
        )

    def get_bucket_tagging(self, **kwargs):
        return self._call(
            "get_bucket_tagging", getattr(self, "tagging", {"TagSet": []}), **kwargs
        )

    def get_public_access_block(self, **kwargs):
        return self._call(
            "get_public_access_block",
            getattr(
                self,
                "pab",
                {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            ),
            **kwargs,
        )

    def get_bucket_policy(self, **kwargs):
        return self._call(
            "get_bucket_policy",
            getattr(self, "policy", {"Policy": '{"Statement": []}'}),
            **kwargs,
        )

    def get_bucket_acl(self, **kwargs):
        return self._call(
            "get_bucket_acl", {"Owner": {"ID": "owner"}, "Grants": []}, **kwargs
        )

    def get_bucket_policy_status(self, **kwargs):
        return self._call(
            "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": False}}, **kwargs
        )


def test_s3_empty_inventory_is_successful() -> None:
    outcome = S3Collector(client=FakeS3()).collect(uuid4())

    assert outcome.resources == []
    assert outcome.result.status is CollectorStatus.SUCCESS
    assert outcome.result.resources_discovered == 0


def test_s3_normalizes_bucket_metadata_and_tags() -> None:
    client = FakeS3(
        [
            {
                "Buckets": [
                    {
                        "Name": "example",
                        "CreationDate": datetime(2026, 1, 1, tzinfo=UTC),
                    }
                ]
            }
        ]
    )
    client.location = {"LocationConstraint": "eu-west-1"}
    client.tagging = {"TagSet": [{"Key": "environment", "Value": "test"}]}
    client.policy = {"Policy": '{"Statement": [{"Effect": "Deny"}]}'}
    scan_id = uuid4()

    outcome = S3Collector(client=client).collect(scan_id)
    resource = outcome.resources[0]

    assert resource.scan_id == scan_id
    assert resource.resource_type == "s3_bucket"
    assert resource.region == "eu-west-1"
    assert resource.tags == {"environment": "test"}
    assert (
        resource.raw_metadata["policy"]["document"]["Statement"][0]["Effect"] == "Deny"
    )
    assert resource.raw_metadata["acl"]["Grants"] == []
    assert outcome.result.status is CollectorStatus.SUCCESS
    assert not {name for name, _ in client.calls} & {
        "create_bucket",
        "put_bucket_policy",
    }


def test_s3_null_location_means_us_east_1_and_absent_optional_config_is_not_error() -> (
    None
):
    client = FakeS3([{"Buckets": [{"Name": "bucket"}]}])
    absence_codes = {
        "get_bucket_tagging": "NoSuchTagSet",
        "get_public_access_block": "NoSuchPublicAccessBlockConfiguration",
        "get_bucket_policy": "NoSuchBucketPolicy",
        "get_bucket_policy_status": "NoSuchBucketPolicy",
    }
    for operation, code in absence_codes.items():
        client.failures[operation] = ClientError({"Error": {"Code": code}}, operation)

    outcome = S3Collector(client=client).collect(uuid4())

    assert outcome.resources[0].region == "us-east-1"
    assert outcome.resources[0].raw_metadata["public_access_block"] == {
        "status": "absent"
    }
    assert outcome.resources[0].raw_metadata["policy"] == {"status": "absent"}
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_s3_uses_continuation_token_for_all_pages() -> None:
    client = FakeS3(
        [
            {"Buckets": [{"Name": "one"}], "ContinuationToken": "page-2"},
            {"Buckets": [{"Name": "two"}]},
        ]
    )

    outcome = S3Collector(client=client).collect(uuid4())

    assert [item.resource_id for item in outcome.resources] == ["one", "two"]
    assert client.calls[1] == ("list_buckets", {"ContinuationToken": "page-2"})
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_s3_invalid_policy_document_is_preserved_and_marks_partial_coverage() -> None:
    client = FakeS3([{"Buckets": [{"Name": "bucket"}]}])
    client.policy = {"Policy": "{not-json"}

    outcome = S3Collector(client=client).collect(uuid4())

    assert outcome.resources[0].raw_metadata["policy"] == {
        "status": "invalid",
        "raw_policy": "{not-json",
        "parse_status": "invalid_json",
    }
    assert outcome.result.status is CollectorStatus.PARTIAL
    assert outcome.result.errors[0].operation == "GetBucketPolicy"


def test_s3_preserves_first_page_resources_when_later_page_fails() -> None:
    class SecondPageFailure(FakeS3):
        def list_buckets(self, **kwargs):
            if kwargs:
                raise RuntimeError("later page unavailable")
            return super().list_buckets(**kwargs)

    client = SecondPageFailure(
        [{"Buckets": [{"Name": "one"}], "ContinuationToken": "page-2"}]
    )

    outcome = S3Collector(client=client).collect(uuid4())

    assert [resource.resource_id for resource in outcome.resources] == ["one"]
    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].operation == "ListBuckets"


def test_s3_repeated_continuation_token_fails_incomplete_inventory() -> None:
    client = FakeS3(
        [
            {"Buckets": [{"Name": "one"}], "ContinuationToken": "page-2"},
            {"Buckets": [{"Name": "two"}], "ContinuationToken": "page-2"},
        ]
    )

    outcome = S3Collector(client=client).collect(uuid4())

    assert [resource.resource_id for resource in outcome.resources] == ["one", "two"]
    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].operation == "ListBuckets"


def test_s3_empty_continuation_token_fails_incomplete_inventory() -> None:
    client = FakeS3([{"Buckets": [], "ContinuationToken": ""}])

    outcome = S3Collector(client=client).collect(uuid4())

    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].operation == "ListBuckets"


def test_s3_enrichment_uses_each_bucket_region(
    monkeypatch,
) -> None:
    class RegionalInventory(FakeS3):
        def get_bucket_location(self, **kwargs):
            regions = {"east-bucket": "us-east-1", "eu-bucket": "eu-west-1"}
            return self._call(
                "get_bucket_location",
                {"LocationConstraint": regions[kwargs["Bucket"]]},
                **kwargs,
            )

    config = load_config({"CSPM_TARGET": "aws", "CSPM_REGION": "us-east-1"})
    inventory_client = RegionalInventory(
        [{"Buckets": [{"Name": "east-bucket"}, {"Name": "eu-bucket"}]}]
    )
    regional_client = FakeS3()
    regional_clients = {"eu-west-1": regional_client}
    factory_calls = []

    def regional_factory(service, received_config, *, region_name):
        factory_calls.append((service, received_config, region_name))
        return regional_clients[region_name]

    monkeypatch.setattr(s3_module, "create_client", regional_factory)
    outcome = S3Collector(config=config, client=inventory_client).collect(uuid4())

    assert factory_calls == [("s3", config, "eu-west-1")]
    assert inventory_client.calls[0] == ("list_buckets", {"MaxBuckets": 1000})
    assert [resource.region for resource in outcome.resources] == [
        "us-east-1",
        "eu-west-1",
    ]
    regional_operations = {name for name, _ in regional_client.calls}
    assert regional_operations == {
        "get_bucket_tagging",
        "get_public_access_block",
        "get_bucket_policy",
        "get_bucket_acl",
        "get_bucket_policy_status",
    }
    assert all(kwargs["Bucket"] == "eu-bucket" for _, kwargs in regional_client.calls)
    assert outcome.result.status is CollectorStatus.SUCCESS


def test_s3_inventory_failure_is_failed_and_enrichment_failure_is_partial() -> None:
    failed_client = FakeS3()
    failed_client.failures["list_buckets"] = RuntimeError("safe failure")
    failed = S3Collector(client=failed_client).collect(uuid4())
    assert failed.result.status is CollectorStatus.FAILED

    partial_client = FakeS3([{"Buckets": [{"Name": "bucket"}]}])
    partial_client.failures["get_bucket_acl"] = RuntimeError("ACL failure")
    partial = S3Collector(client=partial_client).collect(uuid4())
    assert len(partial.resources) == 1
    assert partial.resources[0].raw_metadata["acl"] == {"status": "error"}
    assert partial.result.status is CollectorStatus.PARTIAL
    assert partial.result.errors[0].message == "GetBucketAcl failed (RuntimeError)."


def test_s3_access_denied_is_reported_without_service_message() -> None:
    client = FakeS3()
    client.failures["list_buckets"] = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "secret test content is not exposed",
            }
        },
        "ListBuckets",
    )

    outcome = S3Collector(client=client).collect(uuid4())

    assert outcome.result.status is CollectorStatus.FAILED
    assert outcome.result.errors[0].error_code == "AccessDenied"
    assert "secret test content" not in outcome.result.errors[0].message
