"""Deterministic, in-memory assessment using registered rules."""

from __future__ import annotations

import re
from collections.abc import Iterable
from copy import copy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from cspm.config import CSPMConfig, load_config
from cspm.models.finding import Finding
from cspm.models.fingerprint import generate_fingerprint
from cspm.models.resource import Resource
from cspm.models.rule import Rule
from cspm.rules.base import BaseRule, EvaluationStatus, RuleEvaluation

if TYPE_CHECKING:
    from cspm.persistence import ScanRepository


@dataclass(frozen=True)
class EvaluationRecord:
    """Outcome for one rule/resource pair, possibly with both finding and errors."""

    resource_id: str
    resource_type: str
    rule_id: str | None
    status: EvaluationStatus
    finding: Finding | None = None
    error_code: str | None = None
    message: str | None = None
    detail_code: str | None = None
    error_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssessmentResult:
    """Findings and explicit outcomes from an in-memory assessment.

    An empty ``findings`` tuple does not establish a clean assessment; callers
    should check ``is_complete`` and inspect ``errors``.
    """

    evaluations: tuple[EvaluationRecord, ...]

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return findings in deterministic evaluation order."""
        return tuple(
            evaluation.finding
            for evaluation in self.evaluations
            if evaluation.finding is not None
        )

    @property
    def errors(self) -> tuple[EvaluationRecord, ...]:
        """Return incomplete evaluations without treating them as passes."""
        return tuple(
            evaluation
            for evaluation in self.evaluations
            if (
                evaluation.status is EvaluationStatus.ERROR
                or evaluation.error_code is not None
                or evaluation.error_codes
            )
        )

    @property
    def is_complete(self) -> bool:
        """Whether every applicable evaluation completed without errors."""
        return not self.errors


class AssessmentEngine:
    """Register rules and evaluate resources without AWS or persistence access."""

    def __init__(
        self,
        rules: Iterable[BaseRule] | None = None,
        *,
        config: CSPMConfig | None = None,
    ) -> None:
        self._rules: dict[str, BaseRule] = {}
        if rules is None:
            from cspm.rules import built_in_rules

            active_config = config if config is not None else load_config()
            rules = built_in_rules(active_config)
        for rule in rules:
            self.register(rule)

    @property
    def rules(self) -> tuple[BaseRule, ...]:
        """Return detached rule copies ordered by stable identifier."""
        return tuple(
            _copy_rule_with_definition(self._rules[key]) for key in sorted(self._rules)
        )

    @property
    def catalogue(self) -> tuple[Rule, ...]:
        """Return defensive copies of the registered rule metadata."""
        return tuple(
            self._rules[key].definition.model_copy(deep=True)
            for key in sorted(self._rules)
        )

    def load_rules(self, repository: ScanRepository) -> tuple[Rule, ...]:
        """Refresh stored rule definitions from this engine's registered catalogue."""
        definitions = self.catalogue
        repository.sync_rules(definitions)
        return definitions

    def register(self, rule: BaseRule) -> None:
        """Register a rule instance, rejecting invalid or duplicate identifiers."""
        if not isinstance(rule, BaseRule) or not isinstance(
            getattr(rule, "definition", None), Rule
        ):
            raise TypeError("rule must be a BaseRule with valid Rule metadata")
        registered_rule = _copy_rule_with_definition(rule)
        rule_id = registered_rule.rule_id
        if rule_id in self._rules:
            raise ValueError(f"duplicate rule identifier: {rule_id}")
        self._rules[rule_id] = registered_rule

    def evaluate(self, resources: Iterable[Resource]) -> AssessmentResult:
        """Evaluate applicable rules and retain every pass, finding, or error."""
        materialized = tuple(resources)
        if any(not isinstance(resource, Resource) for resource in materialized):
            raise TypeError("resources must contain only Resource instances")

        records: list[EvaluationRecord] = []
        ordered_resources = sorted(
            materialized,
            key=lambda resource: (
                str(resource.scan_id),
                resource.resource_type,
                resource.resource_id,
            ),
        )
        for resource in ordered_resources:
            matching = [
                self._rules[key]
                for key in sorted(self._rules)
                if self._rules[key].resource_type == resource.resource_type
            ]
            if not matching:
                records.append(
                    self._error_record(
                        resource,
                        None,
                        "UnsupportedResourceType",
                        "No registered rule applies to this resource type.",
                    )
                )
                continue
            for rule in matching:
                records.append(self._evaluate_one(rule, resource))
        return AssessmentResult(tuple(records))

    def _evaluate_one(self, rule: BaseRule, resource: Resource) -> EvaluationRecord:
        try:
            outcome = rule.evaluate(resource)
        except Exception as exc:
            code = _safe_error_code(type(exc).__name__)
            return self._error_record(
                resource,
                rule.rule_id,
                code,
                f"Rule evaluation failed ({code}).",
            )

        if not isinstance(outcome, RuleEvaluation) or not isinstance(
            outcome.status, EvaluationStatus
        ):
            return self._error_record(
                resource,
                rule.rule_id,
                "InvalidRuleResult",
                "Rule returned an invalid evaluation result.",
            )
        if outcome.status is EvaluationStatus.ERROR:
            if (
                outcome.evidence is not None
                or outcome.detail_code is not None
                or not _valid_error_codes(outcome.error_codes, outcome.error_code)
            ):
                return self._error_record(
                    resource,
                    rule.rule_id,
                    "InvalidRuleResult",
                    "Rule returned inconsistent error data.",
                )
            code = _safe_error_code(outcome.error_code)
            return self._error_record(
                resource,
                rule.rule_id,
                code,
                f"Rule evaluation is incomplete ({code}).",
                error_codes=tuple(
                    dict.fromkeys(
                        _safe_error_code(item) for item in outcome.error_codes
                    )
                ),
            )
        if outcome.status is EvaluationStatus.PASSED:
            if (
                outcome.evidence is not None
                or outcome.error_code is not None
                or not isinstance(outcome.error_codes, tuple)
                or outcome.error_codes
            ):
                return self._error_record(
                    resource,
                    rule.rule_id,
                    "InvalidRuleResult",
                    "Rule returned inconsistent pass data.",
                )
            detail_code = (
                _safe_error_code(outcome.detail_code)
                if outcome.detail_code is not None
                else None
            )
            return EvaluationRecord(
                resource.resource_id,
                resource.resource_type,
                rule.rule_id,
                EvaluationStatus.PASSED,
                detail_code=detail_code,
            )
        if (
            outcome.evidence is None
            or outcome.error_code is not None
            or outcome.detail_code is not None
            or not isinstance(outcome.error_codes, tuple)
            or any(
                not isinstance(code, str) or not code.strip()
                for code in outcome.error_codes
            )
        ):
            return self._error_record(
                resource,
                rule.rule_id,
                "InvalidRuleResult",
                "Rule returned an invalid finding result.",
            )
        try:
            finding = Finding(
                finding_id=uuid4(),
                fingerprint=generate_fingerprint(
                    rule.rule_id, resource.resource_type, resource.resource_id
                ),
                scan_id=resource.scan_id,
                rule_id=rule.rule_id,
                resource_id=resource.resource_id,
                title=rule.title,
                severity=rule.severity,
                cis_control=rule.cis_control,
                remediation=rule.remediation_text,
                evidence=outcome.evidence,
                detected_at=datetime.now(UTC),
            )
        except Exception:
            return self._error_record(
                resource,
                rule.rule_id,
                "InvalidFindingData",
                "Finding could not be constructed from rule evidence.",
            )
        error_codes = tuple(
            dict.fromkeys(_safe_error_code(code) for code in outcome.error_codes)
        )
        if error_codes:
            return EvaluationRecord(
                resource.resource_id,
                resource.resource_type,
                rule.rule_id,
                EvaluationStatus.ERROR,
                finding=finding,
                error_code=error_codes[0],
                message=f"Rule evaluation is incomplete ({', '.join(error_codes)}).",
                error_codes=error_codes,
            )
        return EvaluationRecord(
            resource.resource_id,
            resource.resource_type,
            rule.rule_id,
            EvaluationStatus.FINDING,
            finding=finding,
        )

    @staticmethod
    def _error_record(
        resource: Resource,
        rule_id: str | None,
        error_code: str,
        message: str,
        *,
        error_codes: tuple[str, ...] = (),
    ) -> EvaluationRecord:
        safe_codes = tuple(
            dict.fromkeys(
                (_safe_error_code(error_code),)
                + tuple(_safe_error_code(code) for code in error_codes)
            )
        )
        return EvaluationRecord(
            resource.resource_id,
            resource.resource_type,
            rule_id,
            EvaluationStatus.ERROR,
            error_code=safe_codes[0],
            message=message,
            error_codes=safe_codes,
        )


def _valid_error_codes(codes: object, primary_code: object) -> bool:
    """Check that error outcomes carry a well-formed primary and code tuple."""
    return (
        isinstance(primary_code, str)
        and bool(primary_code.strip())
        and isinstance(codes, tuple)
        and (not codes or codes[0] == primary_code)
        and all(isinstance(code, str) and code.strip() for code in codes)
    )


def _copy_rule_with_definition(rule: BaseRule) -> BaseRule:
    """Copy rule state and bind a detached snapshot of its class metadata."""
    result = copy(rule)
    object.__setattr__(result, "definition", rule.definition.model_copy(deep=True))
    return result


def _safe_error_code(value: object) -> str:
    """Keep evaluation errors short and free of exception text or user data."""
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value):
        return value
    return "EvaluationError"
