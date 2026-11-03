from uuid import uuid4

from cspm.collectors.base import CollectorCollection
from cspm.collectors.discovery import DiscoveryEngine
from cspm.models.collector import CollectorError, CollectorResult
from cspm.models.enums import CollectorStatus
from cspm.models.resource import Resource


class FixedCollector:
    name = "fixed"

    def __init__(self, collection=None, error=None):
        self.collection = collection
        self.error = error
        self.scan_ids = []

    def collect(self, scan_id):
        self.scan_ids.append(scan_id)
        if self.error:
            raise self.error
        return self.collection


def test_discovery_aggregates_resources_and_preserves_each_result_and_scan_id() -> None:
    scan_id = uuid4()
    resource = Resource(
        scan_id=scan_id,
        resource_id="sg-1",
        resource_type="security_group",
        region="us-east-1",
    )
    success = FixedCollector(
        CollectorCollection(
            [resource],
            CollectorResult(
                collector_name="ec2",
                status=CollectorStatus.SUCCESS,
                resources_discovered=1,
            ),
        )
    )
    partial = FixedCollector(
        CollectorCollection(
            [],
            CollectorResult(
                collector_name="iam",
                status=CollectorStatus.PARTIAL,
                resources_discovered=0,
                errors=[
                    CollectorError(error_code="AccessDenied", message="GetRole failed")
                ],
            ),
        )
    )

    result = DiscoveryEngine(collectors=[success, partial]).discover(scan_id)

    assert result.resources == [resource]
    assert [item.status for item in result.collector_results] == [
        CollectorStatus.SUCCESS,
        CollectorStatus.PARTIAL,
    ]
    assert success.scan_ids == [scan_id]
    assert partial.scan_ids == [scan_id]


def test_discovery_turns_unexpected_collector_exception_into_failed_coverage() -> None:
    scan_id = uuid4()
    result = DiscoveryEngine(
        collectors=[FixedCollector(error=RuntimeError("failure"))]
    ).discover(scan_id)

    assert result.resources == []
    assert result.collector_results[0].status is CollectorStatus.FAILED
    assert result.collector_results[0].errors[0].error_code == "RuntimeError"


def test_discovery_all_successful_collectors_preserves_complete_results() -> None:
    scan_id = uuid4()
    collectors = [
        FixedCollector(
            CollectorCollection(
                [],
                CollectorResult(
                    collector_name=name,
                    status=CollectorStatus.SUCCESS,
                    resources_discovered=0,
                ),
            )
        )
        for name in ("s3", "iam", "ec2")
    ]

    result = DiscoveryEngine(collectors=collectors).discover(scan_id)

    assert result.resources == []
    assert len(result.collector_results) == 3
    assert all(
        item.status is CollectorStatus.SUCCESS for item in result.collector_results
    )
    assert all(collector.scan_ids == [scan_id] for collector in collectors)


def test_discovery_preserves_successful_collectors_when_one_fails() -> None:
    scan_id = uuid4()
    resource = Resource(
        scan_id=scan_id,
        resource_id="bucket",
        resource_type="s3_bucket",
        region="us-east-1",
    )
    success = FixedCollector(
        CollectorCollection(
            [resource],
            CollectorResult(
                collector_name="s3",
                status=CollectorStatus.SUCCESS,
                resources_discovered=1,
            ),
        )
    )
    failure = FixedCollector(error=RuntimeError("inventory failure"))
    other_success = FixedCollector(
        CollectorCollection(
            [],
            CollectorResult(
                collector_name="ec2",
                status=CollectorStatus.SUCCESS,
                resources_discovered=0,
            ),
        )
    )

    result = DiscoveryEngine(collectors=[success, failure, other_success]).discover(
        scan_id
    )

    assert result.resources == [resource]
    assert [item.status for item in result.collector_results] == [
        CollectorStatus.SUCCESS,
        CollectorStatus.FAILED,
        CollectorStatus.SUCCESS,
    ]
