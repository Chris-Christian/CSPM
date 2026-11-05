"""End-to-end persistence coverage using a temporary SQLite database only."""

from datetime import UTC, datetime
from uuid import uuid4

from cspm.models import Finding, Resource, Rule, Scan, ScanStatus, Severity, TargetType
from cspm.persistence import ScanRepository
from cspm.rules import AssessmentResult, EvaluationRecord, EvaluationStatus


def test_scan_resource_finding_rule_and_assessment_error_round_trip(tmp_path) -> None:
    repository = ScanRepository(tmp_path / "integration.sqlite3")
    repository.initialize()
    scan_id = uuid4()
    scan = Scan(
        scan_id=scan_id,
        target=TargetType.LOCALSTACK,
        region="us-east-1",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        status=ScanStatus.COMPLETED,
    )
    resource = Resource(
        scan_id=scan_id,
        resource_id="integration-bucket",
        resource_type="s3_bucket",
        region="us-east-1",
        raw_metadata={"label": "雪☃", "nested": [1, {"enabled": True}]},
        tags={"purpose": "persistence-test"},
    )
    rule = Rule(
        rule_id="S3-TEST",
        title="Integration persistence rule",
        resource_type="s3_bucket",
        severity=Severity.HIGH,
        remediation_text="Review the test finding.",
    )
    finding = Finding(
        finding_id=uuid4(),
        fingerprint="v1:" + "b" * 64,
        scan_id=scan_id,
        rule_id=rule.rule_id,
        resource_id=resource.resource_id,
        title="Confirmed test finding",
        severity=Severity.HIGH,
        remediation="Review the resource configuration.",
        evidence={"observed": {"principal": "*"}},
        detected_at=datetime.now(UTC),
    )
    evaluation_error = EvaluationRecord(
        resource_id=resource.resource_id,
        resource_type=resource.resource_type,
        rule_id=rule.rule_id,
        status=EvaluationStatus.ERROR,
        finding=finding,
        error_code="UnsupportedCondition",
        message="The condition could not be evaluated.",
        error_codes=("UnsupportedCondition",),
    )

    repository.create_scan(scan)
    repository.save_resources([resource])
    repository.sync_rules([rule])
    repository.persist_assessment(scan_id, AssessmentResult((evaluation_error,)))

    stored_scan = repository.get_scan(scan_id)
    stored_errors = repository.get_assessment_errors(scan_id)
    assert stored_scan is not None and stored_scan.status is ScanStatus.COMPLETED
    assert repository.get_resources(scan_id) == [resource]
    assert repository.get_rules() == [rule]
    assert repository.get_findings(scan_id) == [finding]
    assert stored_errors is not None and len(stored_errors) == 1
    assert stored_errors[0].finding == finding
    assert stored_errors[0].error_code == "UnsupportedCondition"
