"""Contracts shared by independently testable assessment rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.models.rule import Rule


class EvaluationStatus(StrEnum):
    """Possible outcomes when a rule evaluates one resource."""

    PASSED = "passed"
    FINDING = "finding"
    ERROR = "error"


@dataclass(frozen=True)
class RuleEvaluation:
    """Structured result, including independently discovered evidence errors."""

    status: EvaluationStatus
    evidence: object | None = None
    error_code: str | None = None
    detail_code: str | None = None
    error_codes: tuple[str, ...] = ()

    @classmethod
    def passed(cls, detail_code: str | None = None) -> "RuleEvaluation":
        """Return an explicit clean result."""
        return cls(EvaluationStatus.PASSED, detail_code=detail_code)

    @classmethod
    def finding(
        cls, evidence: object, *, error_codes: tuple[str, ...] = ()
    ) -> "RuleEvaluation":
        """Return confirmed violation evidence and any incomplete-evidence codes."""
        return cls(
            EvaluationStatus.FINDING, evidence=evidence, error_codes=error_codes
        )

    @classmethod
    def error(
        cls, error_code: str, *, other_error_codes: tuple[str, ...] = ()
    ) -> "RuleEvaluation":
        """Return an incomplete evaluation without creating a finding."""
        return cls(
            EvaluationStatus.ERROR,
            error_code=error_code,
            error_codes=(error_code, *other_error_codes),
        )


class BaseRule(ABC):
    """Abstract rule contract backed by the existing Rule metadata model."""

    definition: ClassVar[Rule]

    @property
    def rule_id(self) -> str:
        """Stable identifier for this rule."""
        return self.definition.rule_id

    @property
    def title(self) -> str:
        """Human-readable rule title."""
        return self.definition.title

    @property
    def resource_type(self) -> str:
        """Resource type accepted by this rule."""
        return self.definition.resource_type

    @property
    def severity(self) -> Severity:
        """Severity assigned to findings from this rule."""
        return self.definition.severity

    @property
    def cis_control(self) -> str | None:
        """Verified CIS control mapping, if one has been selected."""
        return self.definition.cis_control

    @property
    def cis_version(self) -> str | None:
        """CIS benchmark edition for a verified mapping, if available."""
        return self.definition.cis_version

    @property
    def remediation_text(self) -> str:
        """Remediation guidance included in findings."""
        return self.definition.remediation_text

    def require_resource_type(self, resource: Resource) -> None:
        """Reject direct evaluation of an unrelated resource type."""
        if resource.resource_type != self.resource_type:
            raise ValueError("resource type does not match this rule")

    @abstractmethod
    def evaluate(self, resource: Resource) -> RuleEvaluation:
        """Evaluate a matching resource without mutating it or calling AWS."""
