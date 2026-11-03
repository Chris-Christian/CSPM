"""Rules for confirmed effective public access to S3 buckets."""

from collections.abc import Mapping

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.models.rule import Rule
from cspm.rules.base import BaseRule, RuleEvaluation

_PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
_PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
_ACL_PERMISSIONS = {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}


class S3PublicPolicyRule(BaseRule):
    """Find bucket policies classified public unless PAB blocks public access."""

    definition = Rule(
        rule_id="S3-001",
        title="S3 bucket policy allows public access",
        resource_type="s3_bucket",
        severity=Severity.HIGH,
        remediation_text=(
            "Remove public principals from the bucket policy or restrict access "
            "to explicitly authorized principals."
        ),
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        metadata = resource.raw_metadata
        policy_status = metadata.get("policy_status")
        policy = metadata.get("policy")
        if not isinstance(policy_status, Mapping) or not isinstance(policy, Mapping):
            return RuleEvaluation.error("MissingPolicyEvidence")

        policy_status_state = policy_status.get("status")
        policy_state = policy.get("status")
        if policy_status_state == "absent":
            if policy_state == "absent":
                return RuleEvaluation.passed("NoBucketPolicy")
            return RuleEvaluation.error("ConflictingPolicyEvidence")
        if (
            policy_status_state != "present"
            or type(policy_status.get("is_public")) is not bool
        ):
            return RuleEvaluation.error("InvalidPolicyStatus")
        if policy_state != "present" or not isinstance(policy.get("document"), Mapping):
            return RuleEvaluation.error("InvalidPolicyDocument")
        if not policy_status["is_public"]:
            return RuleEvaluation.passed("PolicyNotPublic")

        flags, error = _public_access_block(metadata)
        if error is not None:
            return RuleEvaluation.error(error)
        assert flags is not None
        if flags["RestrictPublicBuckets"]:
            return RuleEvaluation.passed("BlockedByRestrictPublicBuckets")
        return RuleEvaluation.finding(
            {
                "policy_status": {"is_public": True},
                "public_access_block": {
                    "RestrictPublicBuckets": flags["RestrictPublicBuckets"],
                    "BlockPublicPolicy": flags["BlockPublicPolicy"],
                },
            }
        )


class S3PublicAclRule(BaseRule):
    """Find effective public ACL grants not ignored by bucket-level PAB."""

    definition = Rule(
        rule_id="S3-002",
        title="S3 bucket ACL grants public access",
        resource_type="s3_bucket",
        severity=Severity.HIGH,
        remediation_text=(
            "Remove grants to the AllUsers or AuthenticatedUsers groups, or enable "
            "IgnorePublicAcls at the bucket or account level."
        ),
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        acl = resource.raw_metadata.get("acl")
        if not isinstance(acl, Mapping) or not isinstance(acl.get("Grants"), list):
            return RuleEvaluation.error("MissingOrInvalidAcl")

        public_grants: list[dict[str, str]] = []
        errors: list[str] = []
        for grant in acl["Grants"]:
            if not isinstance(grant, Mapping):
                errors.append("InvalidAclGrant")
                continue
            grantee = grant.get("Grantee")
            permission = grant.get("Permission")
            if (
                not isinstance(grantee, Mapping)
                or not isinstance(permission, str)
                or permission not in _ACL_PERMISSIONS
            ):
                errors.append("InvalidAclGrant")
                continue
            uri = grantee.get("URI")
            if uri is not None and not isinstance(uri, str):
                errors.append("InvalidAclGrantee")
                continue
            if uri in _PUBLIC_GROUPS:
                public_grants.append(
                    {"group": uri.rsplit("/", 1)[-1], "permission": permission}
                )

        unique_errors = tuple(dict.fromkeys(errors))
        if not public_grants and not unique_errors:
            return RuleEvaluation.passed("NoPublicAclGrants")
        flags, error = _public_access_block(resource.raw_metadata)
        if error is not None:
            error_codes = tuple(dict.fromkeys((*unique_errors, error)))
            return RuleEvaluation.error(
                error_codes[0], other_error_codes=error_codes[1:]
            )
        assert flags is not None
        if flags["IgnorePublicAcls"]:
            if unique_errors:
                return RuleEvaluation.error(
                    unique_errors[0], other_error_codes=unique_errors[1:]
                )
            return RuleEvaluation.passed("IgnoredByIgnorePublicAcls")
        if not public_grants:
            return RuleEvaluation.error(
                unique_errors[0], other_error_codes=unique_errors[1:]
            )
        return RuleEvaluation.finding(
            {
                "public_grants": public_grants[:20],
                "omitted_grant_count": max(0, len(public_grants) - 20),
                "public_access_block": {
                    "IgnorePublicAcls": flags["IgnorePublicAcls"],
                    "BlockPublicAcls": flags["BlockPublicAcls"],
                },
            },
            error_codes=unique_errors,
        )


class S3PublicAccessBlockRule(BaseRule):
    """Report missing bucket-level Block Public Access protections."""

    definition = Rule(
        rule_id="S3-003",
        title="S3 bucket-level public access block is incomplete",
        resource_type="s3_bucket",
        severity=Severity.MEDIUM,
        remediation_text=(
            "Enable all four bucket-level S3 Block Public Access settings. This "
            "finding identifies incomplete bucket-level controls, not proof that "
            "the bucket is currently public."
        ),
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        flags, error = _public_access_block(resource.raw_metadata)
        if error is not None:
            return RuleEvaluation.error(error)
        assert flags is not None
        disabled_flags = [flag for flag, enabled in flags.items() if not enabled]
        if not disabled_flags:
            return RuleEvaluation.passed("AllBucketLevelPabFlagsEnabled")
        return RuleEvaluation.finding(
            {
                "disabled_bucket_level_flags": disabled_flags,
                "current_public_exposure_confirmed": False,
            }
        )


def _public_access_block(
    metadata: Mapping[str, object],
) -> tuple[dict[str, bool] | None, str | None]:
    """Return known bucket-level PAB flags or an incomplete-evidence code."""
    value = metadata.get("public_access_block")
    if not isinstance(value, Mapping):
        return None, "MissingPublicAccessBlock"
    if value.get("status") == "absent":
        return dict.fromkeys(_PAB_FLAGS, False), None
    configuration = value.get("configuration")
    if (
        value.get("status") != "present"
        or not isinstance(configuration, Mapping)
        or any(type(configuration.get(flag)) is not bool for flag in _PAB_FLAGS)
    ):
        return None, "InvalidPublicAccessBlock"
    return {flag: configuration[flag] for flag in _PAB_FLAGS}, None
