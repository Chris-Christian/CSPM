from datetime import UTC, datetime
from uuid import uuid4

import pytest

from cspm.models import (
    Finding,
    Resource,
    Rule,
    Scan,
    ScanStatus,
    Severity,
    TargetType,
)
from cspm.persistence import ScanRepository
from cspm.reporting.data import FindingReport, ReportData
from cspm.rules import (
    AssessmentResult,
    EvaluationRecord,
    EvaluationStatus,
)

GENERATED_AT = datetime(2026, 11, 5, 12, 30, tzinfo=UTC)


@pytest.fixture
def report_data_factory():
    def build(
        *,
        severities=(Severity.CRITICAL,),
        cis_control="1.2.3",
        errors=None,
        status=ScanStatus.COMPLETED,
        metadata=None,
        tags=None,
        evidence=None,
        title="Public resource",
        remediation="Restrict access.",
    ):
        scan_id = uuid4()
        resources = []
        findings = []
        for index, severity in enumerate(severities):
            resource = Resource(
                scan_id=scan_id,
                resource_id=f"bucket-{index}",
                resource_type="s3_bucket",
                region="us-east-1",
                raw_metadata=(
                    metadata
                    if metadata is not None
                    else {"label": "Public bucket", "nested": [1, True]}
                ),
                tags=tags if tags is not None else {"environment": "test"},
            )
            finding = Finding(
                finding_id=uuid4(),
                fingerprint="v1:" + str(index) * 64,
                scan_id=scan_id,
                rule_id=f"S3-{index:03d}",
                resource_id=resource.resource_id,
                title=title,
                severity=severity,
                cis_control=cis_control,
                remediation=remediation,
                evidence=(
                    evidence
                    if evidence is not None
                    else {"principal": "*", "unicode": "雪☃"}
                ),
                detected_at=datetime(2026, 11, 5, 10, index, tzinfo=UTC),
            )
            resources.append(resource)
            findings.append(FindingReport(finding=finding, resource=resource))

        if not resources:
            resources.append(
                Resource(
                    scan_id=scan_id,
                    resource_id="bucket-0",
                    resource_type="s3_bucket",
                    region="us-east-1",
                    raw_metadata={"label": "Public bucket"},
                )
            )

        scan = Scan(
            scan_id=scan_id,
            target=TargetType.LOCALSTACK,
            region="us-east-1",
            started_at=datetime(2026, 11, 5, 9, tzinfo=UTC),
            completed_at=(
                datetime(2026, 11, 5, 10, tzinfo=UTC)
                if status is not ScanStatus.RUNNING
                else None
            ),
            status=status,
        )
        if errors is ...:
            errors = (
                EvaluationRecord(
                    resource_id="bucket-0",
                    resource_type="s3_bucket",
                    rule_id="S3-000",
                    status=EvaluationStatus.ERROR,
                    error_code="IncompleteEvidence",
                    message="Some evidence could not be evaluated.",
                    error_codes=("IncompleteEvidence",),
                ),
            )
        return ReportData(
            scan=scan,
            resources=tuple(resources),
            findings=tuple(findings),
            assessment_errors=errors,
            generated_at=GENERATED_AT,
        )

    return build


@pytest.fixture
def repository_factory(tmp_path):
    def build(
        *, assessment="not_run", status=ScanStatus.COMPLETED, include_finding=True
    ):
        scan_id = uuid4()
        repository = ScanRepository(tmp_path / "report-test.sqlite3")
        repository.initialize()
        scan = Scan(
            scan_id=scan_id,
            target=TargetType.LOCALSTACK,
            region="us-east-1",
            started_at=datetime(2026, 11, 5, 9, tzinfo=UTC),
            completed_at=(
                None
                if status is ScanStatus.RUNNING
                else datetime(2026, 11, 5, 10, tzinfo=UTC)
            ),
            status=status,
        )
        resource = Resource(
            scan_id=scan_id,
            resource_id="bucket-report",
            resource_type="s3_bucket",
            region="us-east-1",
            raw_metadata={"policy": {"Principal": "*"}},
            tags={"purpose": "report-test"},
        )
        rule = Rule(
            rule_id="S3-REPORT",
            title="Public policy",
            resource_type="s3_bucket",
            severity=Severity.HIGH,
            remediation_text="Restrict the policy.",
        )
        finding = Finding(
            finding_id=uuid4(),
            fingerprint="v1:" + "c" * 64,
            scan_id=scan_id,
            rule_id=rule.rule_id,
            resource_id=resource.resource_id,
            title="Public bucket policy",
            severity=Severity.HIGH,
            cis_control="1.2.3",
            remediation="Restrict access to the bucket.",
            evidence={"principal": "*", "observed": ["雪", 1]},
            detected_at=datetime(2026, 11, 5, 9, 30, tzinfo=UTC),
        )
        repository.create_scan(scan)
        repository.save_resources([resource])
        repository.sync_rules([rule])
        if assessment == "not_run":
            if include_finding:
                repository.save_findings([finding])
        elif assessment == "clean":
            evaluations = (
                (
                    EvaluationRecord(
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        rule_id=rule.rule_id,
                        status=EvaluationStatus.FINDING,
                        finding=finding,
                    ),
                )
                if include_finding
                else ()
            )
            repository.persist_assessment(scan_id, AssessmentResult(evaluations))
        elif assessment == "errors":
            error_records = [
                EvaluationRecord(
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    rule_id=rule.rule_id,
                    status=EvaluationStatus.ERROR,
                    finding=finding if include_finding else None,
                    error_code="IncompleteEvidence",
                    message="Some evidence could not be evaluated.",
                    error_codes=("IncompleteEvidence",),
                )
            ]
            repository.persist_assessment(
                scan_id, AssessmentResult(tuple(error_records))
            )
        else:
            raise ValueError("unsupported test assessment state")
        return repository, scan, resource, finding

    return build
