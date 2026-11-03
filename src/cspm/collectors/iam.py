"""Read-only discovery of IAM roles, managed policies, and inline policies."""

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote
from uuid import UUID

from cspm.collectors.base import Collector, CollectorCollection, result_for, safe_error
from cspm.collectors.normalization import normalize_json, normalize_tags
from cspm.collectors.pagination import PaginationError, collect_pages
from cspm.models.resource import Resource


class IAMCollector(Collector):
    """Discover IAM as global resources, using the ``global`` region convention."""

    name = "iam"
    service_name = "iam"
    region = "global"

    def collect(self, scan_id: UUID) -> CollectorCollection:
        resources: list[Resource] = []
        errors = []
        primary_failed = False
        try:
            roles = collect_pages(self.client.list_roles, "Roles")
        except PaginationError as exc:
            roles = exc.items
            errors.append(safe_error("ListRoles", exc.cause))
            primary_failed = True
        except Exception as exc:
            roles = []
            errors.append(safe_error("ListRoles", exc))
            primary_failed = True
        try:
            listed_policies = collect_pages(
                self.client.list_policies, "Policies", Scope="Local"
            )
        except PaginationError as exc:
            listed_policies = exc.items
            errors.append(safe_error("ListPolicies", exc.cause))
            primary_failed = True
        except Exception as exc:
            listed_policies = []
            errors.append(safe_error("ListPolicies", exc))
            primary_failed = True

        attached: dict[str, Mapping[str, Any]] = {}
        attached_role_names: dict[str, set[str]] = {}
        for role in roles:
            if not isinstance(role, Mapping):
                errors.append(safe_error("ListRoles", ValueError("invalid role")))
                primary_failed = True
                continue
            role_name, role_arn = role.get("RoleName"), role.get("Arn")
            if not isinstance(role_name, str) or not isinstance(role_arn, str):
                errors.append(
                    safe_error("ListRoles", ValueError("role identity missing"))
                )
                primary_failed = True
                continue

            try:
                metadata = normalize_json(dict(role))
            except Exception as exc:
                errors.append(safe_error("NormalizeRole", exc))
                metadata = {
                    "RoleName": role_name,
                    "Arn": role_arn,
                    "metadata_status": "incomplete",
                }
            metadata.update(
                {
                    "attached_managed_policies": [],
                    "inline_policies": [],
                }
            )
            try:
                metadata["permissions_boundary"] = normalize_json(
                    role.get("PermissionsBoundary")
                )
            except Exception as exc:
                errors.append(safe_error("NormalizePermissionsBoundary", exc))
                metadata["permissions_boundary_status"] = "error"
            trust_policy = role.get("AssumeRolePolicyDocument")
            if isinstance(trust_policy, Mapping):
                try:
                    metadata["assume_role_trust_policy"] = normalize_json(trust_policy)
                except Exception as exc:
                    errors.append(safe_error("NormalizeTrustPolicy", exc))
                    metadata["trust_policy_status"] = "error"
            else:
                errors.append(
                    safe_error(
                        "ListRoles", ValueError("trust policy missing or invalid")
                    )
                )
                metadata["trust_policy_status"] = "error"
            try:
                attached_policies = collect_pages(
                    self.client.list_attached_role_policies,
                    "AttachedPolicies",
                    RoleName=role_name,
                )
                for policy in attached_policies:
                    if isinstance(policy, Mapping) and isinstance(
                        policy.get("PolicyArn"), str
                    ):
                        metadata["attached_managed_policies"].append(
                            normalize_json(dict(policy))
                        )
                        attached[policy["PolicyArn"]] = policy
                        attached_role_names.setdefault(policy["PolicyArn"], set()).add(
                            role_name
                        )
            except PaginationError as exc:
                attached_policies = exc.items
                errors.append(safe_error("ListAttachedRolePolicies", exc.cause))
                metadata["attached_managed_policies_status"] = "error"
                for policy in attached_policies:
                    if isinstance(policy, Mapping) and isinstance(
                        policy.get("PolicyArn"), str
                    ):
                        metadata["attached_managed_policies"].append(
                            normalize_json(dict(policy))
                        )
                        attached[policy["PolicyArn"]] = policy
                        attached_role_names.setdefault(policy["PolicyArn"], set()).add(
                            role_name
                        )
            except Exception as exc:
                errors.append(safe_error("ListAttachedRolePolicies", exc))
                metadata["attached_managed_policies_status"] = "error"

            try:
                inline_names = collect_pages(
                    self.client.list_role_policies,
                    "PolicyNames",
                    RoleName=role_name,
                )
            except PaginationError as exc:
                errors.append(safe_error("ListRolePolicies", exc.cause))
                inline_names = exc.items
                metadata["inline_policies_status"] = "error"
            except Exception as exc:
                errors.append(safe_error("ListRolePolicies", exc))
                inline_names = []
                metadata["inline_policies_status"] = "error"

            for policy_name in inline_names:
                if not isinstance(policy_name, str):
                    errors.append(
                        safe_error(
                            "ListRolePolicies", ValueError("invalid policy name")
                        )
                    )
                    continue
                policy_id = f"{role_arn}/inline/{quote(policy_name, safe='')}"
                inline_metadata: dict[str, Any] = {
                    "policy_name": policy_name,
                    "owner_role_name": role_name,
                    "owner_role_arn": role_arn,
                }
                try:
                    response = self.client.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )
                    if "PolicyDocument" not in response:
                        raise ValueError("GetRolePolicy returned an invalid response")
                    document = response["PolicyDocument"]
                    if not isinstance(document, Mapping):
                        raise ValueError("GetRolePolicy returned an invalid document")
                    inline_metadata["policy_document"] = normalize_json(document)
                except Exception as exc:
                    errors.append(safe_error("GetRolePolicy", exc))
                    inline_metadata["policy_document_status"] = "error"
                metadata["inline_policies"].append(policy_id)
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=policy_id,
                        resource_type="iam_policy",
                        region=self.region,
                        raw_metadata=inline_metadata,
                    )
                )

            try:
                role_tag_entries = collect_pages(
                    self.client.list_role_tags,
                    "Tags",
                    RoleName=role_name,
                )
            except PaginationError as exc:
                errors.append(safe_error("ListRoleTags", exc.cause))
                role_tags = {}
                metadata["tags_status"] = "failed"
            else:
                try:
                    role_tags = normalize_tags(role_tag_entries)
                except Exception as exc:
                    errors.append(safe_error("NormalizeRoleTags", exc))
                    role_tags = {}
                    metadata["tags_status"] = "failed"
            try:
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=role_arn,
                        resource_type="iam_role",
                        region=self.region,
                        raw_metadata=metadata,
                        tags=role_tags,
                    )
                )
            except Exception as exc:
                errors.append(safe_error("NormalizeRole", exc))

        policies_by_arn: dict[str, Mapping[str, Any]] = {}
        for policy in listed_policies:
            if isinstance(policy, Mapping) and isinstance(policy.get("Arn"), str):
                policies_by_arn[policy["Arn"]] = policy
            else:
                errors.append(safe_error("ListPolicies", ValueError("invalid policy")))
                primary_failed = True
        policies_by_arn.update(attached)
        for policy_arn, listed_policy in policies_by_arn.items():
            try:
                details_response = self.client.get_policy(PolicyArn=policy_arn)
                details = details_response.get("Policy")
                if not isinstance(details, Mapping):
                    raise ValueError("GetPolicy returned an invalid policy")
                version_id = details.get("DefaultVersionId")
                metadata = normalize_json(dict(details))
                if version_id:
                    version_response = self.client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    version = version_response.get("PolicyVersion")
                    if not isinstance(version, Mapping) or not isinstance(
                        version.get("Document"), Mapping
                    ):
                        raise ValueError(
                            "GetPolicyVersion returned an invalid response"
                        )
                    metadata["policy_document"] = normalize_json(version["Document"])
                else:
                    raise ValueError("IAM policy has no default version")
                metadata["attached_to_roles"] = sorted(
                    attached_role_names.get(policy_arn, set())
                )
                policy_tags = normalize_tags(details.get("Tags", []))
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=policy_arn,
                        resource_type="iam_policy",
                        region=self.region,
                        raw_metadata=metadata,
                        tags=policy_tags,
                    )
                )
            except Exception as exc:
                errors.append(safe_error("GetPolicy/GetPolicyVersion", exc))
                fallback_metadata = {
                    "PolicyArn": policy_arn,
                    "PolicyName": (
                        listed_policy.get("PolicyName")
                        if isinstance(listed_policy.get("PolicyName"), str)
                        else "unknown"
                    ),
                    "policy_document_status": "error",
                }
                try:
                    fallback_tags = normalize_tags(listed_policy.get("Tags", []))
                except Exception:
                    fallback_tags = {}
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=policy_arn,
                        resource_type="iam_policy",
                        region=self.region,
                        raw_metadata=fallback_metadata,
                        tags=fallback_tags,
                    )
                )

        unique_resources = list(
            {
                (resource.resource_type, resource.resource_id): resource
                for resource in reversed(resources)
            }.values()
        )
        unique_resources.reverse()
        return CollectorCollection(
            unique_resources,
            result_for(
                self.name, unique_resources, errors, primary_failed=primary_failed
            ),
        )
