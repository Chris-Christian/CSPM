"""Rules for objectively broad IAM policy permissions and trust policies."""

from collections.abc import Mapping
from fnmatch import fnmatchcase
from typing import Any

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.models.rule import Rule
from cspm.rules.base import BaseRule, RuleEvaluation


class IamWildcardPermissionRule(BaseRule):
    """Find broad Allow statements in collected customer or inline policies."""

    definition = Rule(
        rule_id="IAM-001",
        title="IAM policy grants wildcard permissions",
        resource_type="iam_policy",
        severity=Severity.HIGH,
        remediation_text=(
            "Replace wildcard actions and broad exclusions with the specific actions "
            "and resources required by the workload."
        ),
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        metadata = resource.raw_metadata
        if metadata.get("policy_document_status") == "error":
            return RuleEvaluation.error("PolicyDocumentUnavailable")
        document = metadata.get("policy_document")
        if not isinstance(document, Mapping):
            return RuleEvaluation.error("MissingPolicyDocument")
        raw_statements = document.get("Statement")
        if isinstance(raw_statements, Mapping):
            statements = [raw_statements]
        elif isinstance(raw_statements, list):
            statements = raw_statements
        else:
            return RuleEvaluation.error("InvalidPolicyStatements")

        broad_statements: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping):
                errors.append("InvalidPolicyStatement")
                continue
            effect = statement.get("Effect")
            if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
                errors.append("InvalidPolicyEffect")
                continue
            action_key = _exclusive_selector(statement, "Action", "NotAction")
            resource_key = _exclusive_selector(statement, "Resource", "NotResource")
            if action_key is None or resource_key is None:
                errors.append("InvalidPolicySelector")
                continue
            actions = _string_values(statement[action_key])
            resources = _string_values(statement[resource_key])
            if actions is None or resources is None:
                errors.append("InvalidPolicySelector")
                continue
            if effect == "Deny":
                continue

            reasons: list[str] = []
            broad_actions = [
                action for action in actions if _has_action_wildcard(action)
            ]
            if action_key == "NotAction":
                reasons.append("AllowNotAction")
            if resource_key == "NotResource":
                reasons.append("AllowNotResource")
            if broad_actions:
                reasons.append("WildcardAction")
            wildcard_resources = [value for value in resources if value == "*"]
            if wildcard_resources and broad_actions:
                reasons.append("WildcardResourceWithWildcardAction")
            if not reasons:
                continue
            if "Condition" in statement:
                errors.append("ConditionalBroadPermissionUnsupported")
                continue
            broad_statements.append(
                {
                    "statement_index": index,
                    "reasons": reasons,
                    "actions": actions[:10],
                    "omitted_action_count": max(0, len(actions) - 10),
                    "wildcard_resource": bool(wildcard_resources),
                }
            )

        unique_errors = tuple(dict.fromkeys(errors))
        if broad_statements:
            return RuleEvaluation.finding(
                {
                    "policy_source": (
                        "inline"
                        if isinstance(metadata.get("owner_role_name"), str)
                        else "managed"
                    ),
                    "statements": broad_statements[:20],
                    "omitted_statement_count": max(0, len(broad_statements) - 20),
                },
                error_codes=unique_errors,
            )
        if unique_errors:
            return RuleEvaluation.error(
                unique_errors[0], other_error_codes=unique_errors[1:]
            )
        return RuleEvaluation.passed("NoDetectedWildcardAllow")


class IamWildcardTrustRule(BaseRule):
    """Find unconditional wildcard principals allowed to assume an IAM role."""

    definition = Rule(
        rule_id="IAM-002",
        title="IAM role trust policy accepts any principal",
        resource_type="iam_role",
        severity=Severity.CRITICAL,
        remediation_text=(
            "Restrict the role trust policy to specific AWS accounts, roles, or "
            "services and review any required conditions."
        ),
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        metadata = resource.raw_metadata
        if metadata.get("trust_policy_status") == "error":
            return RuleEvaluation.error("TrustPolicyUnavailable")
        document = metadata.get("assume_role_trust_policy")
        if not isinstance(document, Mapping):
            return RuleEvaluation.error("MissingTrustPolicy")
        raw_statements = document.get("Statement")
        if isinstance(raw_statements, Mapping):
            statements = [raw_statements]
        elif isinstance(raw_statements, list):
            statements = raw_statements
        else:
            return RuleEvaluation.error("InvalidTrustStatements")

        wildcard_statements: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping):
                errors.append("InvalidTrustStatement")
                continue
            effect = statement.get("Effect")
            if not isinstance(effect, str) or effect not in {"Allow", "Deny"}:
                errors.append("InvalidTrustEffect")
                continue
            actions = _string_values(statement.get("Action"))
            if actions is None:
                errors.append("InvalidTrustAction")
                continue
            principal = statement.get("Principal")
            wildcard_keys = _wildcard_principal_keys(principal)
            if wildcard_keys is None:
                errors.append("InvalidTrustPrincipal")
                continue
            if effect == "Deny" or not wildcard_keys:
                continue
            if not any(_action_grants_assume_role(action) for action in actions):
                continue
            if "Condition" in statement:
                errors.append("ConditionalTrustPolicyUnsupported")
                continue
            wildcard_statements.append(
                {
                    "statement_index": index,
                    "wildcard_principal_fields": wildcard_keys,
                    "actions": actions[:10],
                }
            )

        unique_errors = tuple(dict.fromkeys(errors))
        if wildcard_statements:
            return RuleEvaluation.finding(
                {"statements": wildcard_statements[:20]},
                error_codes=unique_errors,
            )
        if unique_errors:
            return RuleEvaluation.error(
                unique_errors[0], other_error_codes=unique_errors[1:]
            )
        return RuleEvaluation.passed("NoUnconditionalWildcardTrust")


def _exclusive_selector(
    statement: Mapping[str, object], positive: str, negative: str
) -> str | None:
    """Return exactly one of a policy's positive/negative selectors."""
    present = [key for key in (positive, negative) if key in statement]
    return present[0] if len(present) == 1 else None


def _string_values(value: object) -> list[str] | None:
    """Normalize a non-empty IAM string or string-list field."""
    if isinstance(value, str) and value.strip():
        return [value]
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item.strip() for item in value)
    ):
        return value
    return None


def _has_action_wildcard(action: str) -> bool:
    """Identify full-action and service-wide wildcards only."""
    normalized = action.lower()
    if normalized == "*":
        return True
    service, separator, operation = normalized.partition(":")
    return bool(service and separator and operation == "*")


_ASSUME_ROLE_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)


def _action_grants_assume_role(action: str) -> bool:
    """True if an IAM action string can match any AssumeRole-family action.

    IAM wildcards are only `*` and `?`; `[` is escaped so fnmatch does not
    treat it as a character class.
    """
    pattern = action.lower().replace("[", "[[]")
    return any(fnmatchcase(name, pattern) for name in _ASSUME_ROLE_ACTIONS)


def _wildcard_principal_keys(principal: object) -> list[str] | None:
    """Return principal fields containing wildcard identities, if well-formed."""
    if principal == "*":
        return ["*"]
    if not isinstance(principal, Mapping) or not principal:
        return None
    wildcard_keys: list[str] = []
    for key, value in principal.items():
        if not isinstance(key, str) or not key:
            return None
        values = _string_values(value)
        if values is None:
            return None
        if "*" in values:
            wildcard_keys.append(key)
    return wildcard_keys
