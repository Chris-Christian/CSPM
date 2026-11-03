"""Tests for rule registration, outcomes, and finding construction."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from cspm.config import load_config
from cspm.models.enums import Severity
from cspm.models.resource import Resource
from cspm.models.rule import Rule
from cspm.rules import (
    AssessmentEngine,
    BaseRule,
    EvaluationStatus,
    RuleEvaluation,
)


def make_resource(resource_id: str = "resource-a", **overrides: object) -> Resource:
    values: dict[str, object] = {
        "scan_id": uuid4(),
        "resource_id": resource_id,
        "resource_type": "test_resource",
        "region": "local",
        "raw_metadata": {"nested": {"value": 1}},
        "tags": {"env": "test"},
    }
    values.update(overrides)
    return Resource(**values)


class FindingRule(BaseRule):
    definition = Rule(
        rule_id="TEST-001",
        title="Test violation",
        resource_type="test_resource",
        severity=Severity.HIGH,
        remediation_text="Fix the test violation.",
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        return RuleEvaluation.finding({"observed": resource.raw_metadata["nested"]})


class PassRule(BaseRule):
    definition = Rule(
        rule_id="TEST-002",
        title="Test pass",
        resource_type="test_resource",
        severity=Severity.LOW,
        remediation_text="No remediation is needed.",
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        self.require_resource_type(resource)
        return RuleEvaluation.passed()


class DuplicateRule(FindingRule):
    pass


class RaisingRule(FindingRule):
    definition = Rule(
        rule_id="TEST-003",
        title="Raises",
        resource_type="test_resource",
        severity=Severity.LOW,
        remediation_text="Retry later.",
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        raise RuntimeError("sensitive exception content")


class MalformedResultRule(FindingRule):
    definition = Rule(
        rule_id="TEST-004",
        title="Malformed result",
        resource_type="test_resource",
        severity=Severity.LOW,
        remediation_text="Fix the result.",
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        return "finding"  # type: ignore[return-value]


class InvalidEvidenceRule(FindingRule):
    definition = Rule(
        rule_id="TEST-005",
        title="Invalid evidence",
        resource_type="test_resource",
        severity=Severity.LOW,
        remediation_text="Fix the evidence.",
    )

    def evaluate(self, resource: Resource) -> RuleEvaluation:
        return RuleEvaluation.finding({"unsupported": object()})


def test_default_catalogue_has_stable_ids_and_unset_cis_mapping() -> None:
    engine = AssessmentEngine(config=load_config({}))

    assert [rule.rule_id for rule in engine.catalogue] == [
        "EC2-001",
        "EC2-002",
        "IAM-001",
        "IAM-002",
        "S3-001",
        "S3-002",
        "S3-003",
    ]
    assert all(
        rule.cis_control is None and rule.cis_version is None
        for rule in engine.catalogue
    )


def test_registration_is_extensible_and_rejects_duplicate_rule_ids() -> None:
    engine = AssessmentEngine(rules=[])
    engine.register(FindingRule())

    assert [rule.rule_id for rule in engine.rules] == ["TEST-001"]
    with pytest.raises(ValueError, match="duplicate rule identifier"):
        engine.register(DuplicateRule())


def test_registered_metadata_is_snapshotted_and_rule_views_are_detached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_engine = AssessmentEngine(rules=[FindingRule()])
    second_engine = AssessmentEngine(rules=[FindingRule()])
    exposed_rule = first_engine.rules[0]
    exposed_rule.definition.rule_id = "MUTATED-999"
    exposed_rule.definition.title = "Mutated exposed title"
    exposed_rule.definition.resource_type = "other_resource"

    monkeypatch.setattr(
        FindingRule,
        "definition",
        Rule(
            rule_id="MUTATED-998",
            title="Mutated class title",
            resource_type="other_resource",
            severity=Severity.LOW,
            remediation_text="Changed after engine registration.",
        ),
    )

    for engine in (first_engine, second_engine):
        assert [rule.rule_id for rule in engine.rules] == ["TEST-001"]
        assert engine.catalogue[0].title == "Test violation"
        result = engine.evaluate([make_resource()])
        assert result.findings[0].title == "Test violation"
        assert result.findings[0].rule_id == "TEST-001"

def test_assessment_completeness_is_derived_and_read_only() -> None:
    complete = AssessmentEngine(rules=[]).evaluate([])
    incomplete = AssessmentEngine(rules=[]).evaluate([make_resource()])

    assert complete.findings == ()
    assert complete.errors == ()
    assert complete.is_complete is True
    assert incomplete.findings == ()
    assert incomplete.errors
    assert incomplete.is_complete is False
    with pytest.raises(FrozenInstanceError):
        incomplete.is_complete = True  # type: ignore[misc]


def test_empty_resources_and_empty_catalogue_are_explicit() -> None:
    assert AssessmentEngine(rules=[]).evaluate([]).evaluations == ()

    result = AssessmentEngine(rules=[]).evaluate([make_resource()])

    assert result.findings == ()
    assert len(result.errors) == 1
    assert result.errors[0].error_code == "UnsupportedResourceType"


def test_findings_are_built_from_rule_metadata_with_stable_fingerprints() -> None:
    resource = make_resource()
    engine = AssessmentEngine(rules=[FindingRule()])

    first = engine.evaluate([resource])
    second = engine.evaluate([resource])
    finding = first.findings[0]

    assert first.evaluations[0].status is EvaluationStatus.FINDING
    assert finding.scan_id == resource.scan_id
    assert finding.rule_id == "TEST-001"
    assert finding.resource_id == resource.resource_id
    assert finding.title == "Test violation"
    assert finding.severity is Severity.HIGH
    assert finding.cis_control is None
    assert finding.remediation == "Fix the test violation."
    assert finding.evidence == {"observed": {"value": 1}}
    assert finding.detected_at.tzinfo is not None
    assert finding.detected_at.utcoffset().total_seconds() == 0
    assert finding.fingerprint == second.findings[0].fingerprint
    assert finding.finding_id != second.findings[0].finding_id


def test_evaluation_order_is_deterministic_and_passes_are_retained() -> None:
    engine = AssessmentEngine(rules=[PassRule(), FindingRule()])
    scan_id = uuid4()
    resources = [
        make_resource("z-resource", scan_id=scan_id),
        make_resource("a-resource", scan_id=scan_id),
    ]

    result = engine.evaluate(resources)

    assert [
        (record.resource_id, record.rule_id, record.status)
        for record in result.evaluations
    ] == [
        ("a-resource", "TEST-001", EvaluationStatus.FINDING),
        ("a-resource", "TEST-002", EvaluationStatus.PASSED),
        ("z-resource", "TEST-001", EvaluationStatus.FINDING),
        ("z-resource", "TEST-002", EvaluationStatus.PASSED),
    ]


def test_builtin_rules_do_not_mutate_resource_input() -> None:
    resource = make_resource(
        resource_type="iam_policy",
        raw_metadata={
            "policy_document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        },
    )
    before_metadata = deepcopy(resource.raw_metadata)
    before_tags = deepcopy(resource.tags)
    engine = AssessmentEngine(config=load_config({}))

    engine.evaluate([resource])

    assert resource.raw_metadata == before_metadata
    assert resource.tags == before_tags


def test_rule_exceptions_and_malformed_results_become_evaluation_errors() -> None:
    engine = AssessmentEngine(rules=[RaisingRule(), MalformedResultRule()])

    result = engine.evaluate([make_resource()])

    assert [item.error_code for item in result.errors] == [
        "RuntimeError",
        "InvalidRuleResult",
    ]
    assert all(
        "sensitive exception content" not in item.message for item in result.errors
    )
    assert result.findings == ()


def test_invalid_finding_evidence_is_an_error_not_a_finding() -> None:
    result = AssessmentEngine(rules=[InvalidEvidenceRule()]).evaluate([make_resource()])

    assert result.findings == ()
    assert result.errors[0].error_code == "InvalidFindingData"


def test_engine_does_not_accept_non_resource_inputs() -> None:
    with pytest.raises(TypeError, match="Resource instances"):
        AssessmentEngine(rules=[]).evaluate([object()])  # type: ignore[list-item]
