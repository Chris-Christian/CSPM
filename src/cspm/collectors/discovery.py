"""Coordinate collectors without persisting scans or changing lifecycle state."""

from dataclasses import dataclass, field
from uuid import UUID

from cspm.collectors.base import (
    Collector,
    CollectorCollection,
    result_for,
    safe_error,
)
from cspm.collectors.ec2 import EC2SecurityGroupCollector
from cspm.collectors.iam import IAMCollector
from cspm.collectors.s3 import S3Collector
from cspm.config import CSPMConfig
from cspm.models.collector import CollectorResult
from cspm.models.resource import Resource


@dataclass(frozen=True)
class DiscoveryResult:
    """Aggregated inventory and individual collector coverage results."""

    resources: list[Resource]
    collector_results: list[CollectorResult]


@dataclass
class DiscoveryEngine:
    """Run S3, IAM, and EC2 collectors for one caller-supplied scan ID."""

    config: CSPMConfig | None = None
    collectors: list[Collector] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.collectors:
            self.collectors = [
                S3Collector(self.config),
                IAMCollector(self.config),
                EC2SecurityGroupCollector(self.config),
            ]

    def discover(self, scan_id: UUID) -> DiscoveryResult:
        """Run each collector and retain each coverage result independently."""
        resources: list[Resource] = []
        results: list[CollectorResult] = []
        for collector in self.collectors:
            try:
                collection: CollectorCollection = collector.collect(scan_id)
            except Exception as exc:
                error = safe_error("Collect", exc)
                results.append(
                    result_for(collector.name, [], [error], primary_failed=True)
                )
                continue
            resources.extend(collection.resources)
            results.append(collection.result)
        return DiscoveryResult(resources=resources, collector_results=results)
