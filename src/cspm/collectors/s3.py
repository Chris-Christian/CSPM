"""Read-only discovery of S3 buckets and their security configuration."""

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from cspm.collectors.base import Collector, CollectorCollection, result_for, safe_error
from cspm.collectors.normalization import normalize_json, normalize_tags
from cspm.models.collector import CollectorError
from cspm.models.resource import Resource

_ABSENT_CONFIGURATION_CODES = {
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "NoSuchTagSet",
}


class S3Collector(Collector):
    """Discover bucket inventory, tags, ACL, public-access block, and policy."""

    name = "s3"
    service_name = "s3"

    def collect(self, scan_id: UUID) -> CollectorCollection:
        resources: list[Resource] = []
        errors: list[CollectorError] = []
        token: str | None = None
        seen_tokens: set[str] = set()
        seen_buckets: set[str] = set()
        primary_failed = False
        try:
            buckets: list[dict[str, Any]] = []
            while True:
                request = {} if token is None else {"ContinuationToken": token}
                response = self.client.list_buckets(**request)
                if not isinstance(response, Mapping) or not isinstance(
                    response.get("Buckets", []), list
                ):
                    raise ValueError("ListBuckets returned an invalid response")
                buckets.extend(response.get("Buckets", []))
                if "ContinuationToken" not in response:
                    break
                next_token = response["ContinuationToken"]
                if (
                    not isinstance(next_token, str)
                    or not next_token
                    or next_token in seen_tokens
                ):
                    raise ValueError(
                        "ListBuckets returned an invalid continuation token"
                    )
                seen_tokens.add(next_token)
                token = next_token
        except Exception as exc:
            errors.append(safe_error("ListBuckets", exc))
            primary_failed = True

        config = self.config
        for bucket in buckets:
            name = bucket.get("Name") if isinstance(bucket, Mapping) else None
            if not isinstance(name, str) or not name:
                errors.append(
                    safe_error("ListBuckets", ValueError("invalid bucket name"))
                )
                primary_failed = True
                continue
            if name in seen_buckets:
                continue
            seen_buckets.add(name)
            metadata: dict[str, Any] = {"name": name}
            try:
                metadata["creation_date"] = normalize_json(bucket.get("CreationDate"))
            except Exception as exc:
                errors.append(safe_error("NormalizeBucketCreationDate", exc))
                metadata["creation_date_status"] = "error"
            bucket_region = config.region
            try:
                location_response = self.client.get_bucket_location(Bucket=name)
                if (
                    not isinstance(location_response, Mapping)
                    or "LocationConstraint" not in location_response
                ):
                    raise ValueError("GetBucketLocation returned an invalid response")
                location = location_response["LocationConstraint"]
                if location is not None and not isinstance(location, str):
                    raise ValueError("GetBucketLocation returned an invalid region")
                location_constraint = location
                if location_constraint == "EU":
                    bucket_region = "eu-west-1"
                else:
                    bucket_region = (
                        "us-east-1"
                        if location_constraint in (None, "")
                        else location_constraint
                    )
                metadata["bucket_location"] = location_constraint
            except Exception as exc:
                errors.append(safe_error("GetBucketLocation", exc))
                metadata["bucket_location"] = {"status": "error"}

            self._enrich(name, "GetBucketTagging", "tags", metadata, errors, self._tags)
            self._enrich(
                name,
                "GetPublicAccessBlock",
                "public_access_block",
                metadata,
                errors,
                self._public_access_block,
            )
            self._enrich(
                name,
                "GetBucketPolicy",
                "policy",
                metadata,
                errors,
                self._policy,
            )
            self._enrich(name, "GetBucketAcl", "acl", metadata, errors, self._acl)
            self._enrich(
                name,
                "GetBucketPolicyStatus",
                "policy_status",
                metadata,
                errors,
                self._policy_status,
            )
            try:
                resources.append(
                    Resource(
                        scan_id=scan_id,
                        resource_id=name,
                        resource_type="s3_bucket",
                        region=bucket_region,
                        raw_metadata=normalize_json(metadata),
                        tags=normalize_tags(
                            metadata.get("tags", {}).get("values", {})
                            if isinstance(metadata.get("tags"), dict)
                            else {}
                        ),
                    )
                )
            except Exception as exc:
                errors.append(safe_error("NormalizeBucket", exc))

        return CollectorCollection(
            resources,
            result_for(self.name, resources, errors, primary_failed=primary_failed),
        )

    def _enrich(
        self,
        bucket: str,
        operation: str,
        key: str,
        metadata: dict[str, Any],
        errors: list[CollectorError],
        getter: Any,
    ) -> None:
        try:
            value = getter(bucket)
            metadata[key] = value
            if isinstance(value, Mapping) and value.get("status") == "invalid":
                errors.append(safe_error(operation, ValueError("invalid response")))
        except Exception as exc:
            code = _error_code(exc)
            if code in _ABSENT_CONFIGURATION_CODES:
                metadata[key] = {"status": "absent"}
            else:
                errors.append(safe_error(operation, exc))
                metadata[key] = {"status": "error"}

    def _tags(self, bucket: str) -> dict[str, Any]:
        response = self.client.get_bucket_tagging(Bucket=bucket)
        if not isinstance(response, Mapping) or not isinstance(
            response.get("TagSet"), list
        ):
            raise ValueError("GetBucketTagging returned an invalid response")
        return {
            "status": "present",
            "values": normalize_tags(response["TagSet"]),
        }

    def _public_access_block(self, bucket: str) -> dict[str, Any]:
        response = self.client.get_public_access_block(Bucket=bucket)
        configuration = response.get("PublicAccessBlockConfiguration")
        required_flags = {
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        }
        if (
            not isinstance(configuration, Mapping)
            or not required_flags.issubset(configuration)
            or any(type(configuration[key]) is not bool for key in required_flags)
        ):
            raise ValueError("GetPublicAccessBlock returned an invalid response")
        return {
            "status": "present",
            "configuration": normalize_json(configuration),
        }

    def _policy(self, bucket: str) -> dict[str, Any]:
        response = self.client.get_bucket_policy(Bucket=bucket)
        if not isinstance(response, Mapping) or not isinstance(
            response.get("Policy"), str
        ):
            raise ValueError("GetBucketPolicy returned an invalid response")
        document: Any = response["Policy"]
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except json.JSONDecodeError:
                return {
                    "status": "invalid",
                    "raw_policy": document,
                    "parse_status": "invalid_json",
                }
        if not isinstance(document, Mapping):
            return {
                "status": "invalid",
                "raw_policy": response["Policy"],
                "parse_status": "invalid_document",
            }
        return {"status": "present", "document": normalize_json(document)}

    def _acl(self, bucket: str) -> dict[str, Any]:
        response = self.client.get_bucket_acl(Bucket=bucket)
        if not isinstance(response, Mapping) or not isinstance(
            response.get("Grants"), list
        ):
            raise ValueError("GetBucketAcl returned an invalid response")
        acl: dict[str, Any] = {"Grants": normalize_json(response["Grants"])}
        if "Owner" in response:
            acl["Owner"] = normalize_json(response["Owner"])
        return acl

    def _policy_status(self, bucket: str) -> dict[str, Any]:
        response = self.client.get_bucket_policy_status(Bucket=bucket)
        policy_status = response.get("PolicyStatus")
        is_public = (
            policy_status.get("IsPublic")
            if isinstance(policy_status, Mapping)
            else None
        )
        if not isinstance(is_public, bool):
            raise ValueError("GetBucketPolicyStatus returned an invalid response")
        return {"status": "present", "is_public": is_public}


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error", {})
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            return error["Code"]
    return None
