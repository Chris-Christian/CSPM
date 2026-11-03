"""Read-only discovery of EC2 security groups and complete rule data."""

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from cspm.collectors.base import Collector, CollectorCollection, result_for, safe_error
from cspm.collectors.normalization import normalize_json, normalize_tags
from cspm.collectors.pagination import PaginationError, collect_pages
from cspm.models.resource import Resource


class EC2SecurityGroupCollector(Collector):
    """Discover security groups in the configured region."""

    name = "ec2_security_groups"
    service_name = "ec2"

    def collect(self, scan_id: UUID) -> CollectorCollection:
        primary_failed = False
        errors = []
        try:
            groups = collect_pages(
                self.client.describe_security_groups,
                "SecurityGroups",
                MaxResults=1000,
            )
        except PaginationError as exc:
            groups = exc.items
            errors.append(safe_error("DescribeSecurityGroups", exc.cause))
            primary_failed = True
        except Exception as exc:
            groups = []
            errors.append(safe_error("DescribeSecurityGroups", exc))
            primary_failed = True

        resources: list[Resource] = []
        seen_group_ids: set[str] = set()
        for group in groups:
            if not isinstance(group, Mapping):
                errors.append(
                    safe_error("DescribeSecurityGroups", ValueError("invalid group"))
                )
                primary_failed = True
                continue
            group_id = group.get("GroupId")
            if not isinstance(group_id, str) or not group_id:
                errors.append(
                    safe_error("DescribeSecurityGroups", ValueError("group ID missing"))
                )
                primary_failed = True
                continue
            if group_id in seen_group_ids:
                continue
            seen_group_ids.add(group_id)
            group_metadata = dict(group)
            try:
                tags = normalize_tags(group.get("Tags", []))
            except Exception as exc:
                errors.append(safe_error("NormalizeSecurityGroupTags", exc))
                tags = {}
                raw_tags = group_metadata.pop("Tags", None)
                if raw_tags is not None:
                    try:
                        group_metadata["unvalidated_tags"] = normalize_json(raw_tags)
                    except ValueError:
                        pass
                group_metadata["tags_status"] = "failed"
            try:
                metadata: dict[str, Any] = normalize_json(group_metadata)
                for api_key, normalized_key in (
                    ("IpPermissions", "ingress"),
                    ("IpPermissionsEgress", "egress"),
                ):
                    rules = group.get(api_key)
                    if not isinstance(rules, list):
                        errors.append(
                            safe_error(
                                "DescribeSecurityGroups",
                                ValueError(f"{api_key} missing or invalid"),
                            )
                        )
                        metadata[f"{normalized_key}_status"] = "error"
                        rules = []
                    metadata[normalized_key] = normalize_json(rules)
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=group_id,
                        resource_type="security_group",
                        region=self.config.region,
                        raw_metadata=metadata,
                        tags=tags,
                    )
                )
            except Exception as exc:
                errors.append(safe_error("NormalizeSecurityGroup", exc))

        return CollectorCollection(
            resources,
            result_for(self.name, resources, errors, primary_failed=primary_failed),
        )
