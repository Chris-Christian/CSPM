"""Integration checks for the core CSPM models and their relationships."""

from datetime import UTC, datetime
from uuid import uuid4

from cspm.models import (
    CollectorError,
    CollectorResult,
    CollectorStatus,
    Finding,
    Resource,
    Rule,
    Scan,
    ScanStatus,
    Severity,
    TargetType,
    generate_fingerprint,
)


def test_core_models_integrate_relationships_fingerprints_and_json_round_trips(
) -> None:
    scan_id = uuid4()
    scan = Scan(
        scan_id=scan_id,
        target=TargetType.AWS,
        region="us-east-1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        status=ScanStatus.COMPLETED,
        collector_results=[
            CollectorResult(
                collector_name="s3",
                status=CollectorStatus.SUCCESS,
                resources_discovered=2,
            ),
            CollectorResult(
                collector_name="iam",
                status=CollectorStatus.PARTIAL,
                resources_discovered=1,
                errors=[
                    CollectorError(
                        error_code="AccessDenied",
                        message="One role could not be read.",
                        operation="GetRole",
                    )
                ],
            ),
        ],
    )

    resources = [
        Resource(
            scan_id=scan_id,
            resource_id="bucket-a",
            resource_type="s3_bucket",
            region="us-east-1",
            raw_metadata={"public": True},
            tags={"environment": "prod"},
        ),
        Resource(
            scan_id=scan_id,
            resource_id="bucket-b",
            resource_type="s3_bucket",
            region="us-east-1",
            raw_metadata={"public": True},
        ),
        Resource(
            scan_id=scan_id,
            resource_id="role-a",
            resource_type="iam_role",
            region="us-east-1",
            raw_metadata={"trust_policy": {"principal": "*"}},
        ),
    ]
    rules = [
        Rule(
            rule_id="S3-001",
            title="Block public bucket access",
            resource_type="s3_bucket",
            severity=Severity.HIGH,
            cis_control="2.1.5",
            cis_version="1.5",
            remediation_text="Block public access.",
        ),
        Rule(
            rule_id="IAM-001",
            title="Restrict role trust policy",
            resource_type="iam_role",
            severity=Severity.CRITICAL,
            remediation_text="Limit trusted principals.",
        ),
    ]

    rules_by_id = {rule.rule_id: rule for rule in rules}
    resources_by_identity = {
        (resource.scan_id, resource.resource_id): resource for resource in resources
    }
    findings = [
        Finding(
            finding_id=uuid4(),
            fingerprint=generate_fingerprint(
                "S3-001", resources[0].resource_type, resources[0].resource_id
            ),
            scan_id=scan_id,
            rule_id="S3-001",
            resource_id="bucket-a",
            title="Bucket is public",
            severity=Severity.HIGH,
            cis_control="2.1.5",
            remediation="Block public access.",
            evidence={"public": True, "acl": ["AllUsers"]},
            detected_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        ),
        Finding(
            finding_id=uuid4(),
            fingerprint=generate_fingerprint(
                "S3-001", resources[1].resource_type, resources[1].resource_id
            ),
            scan_id=scan_id,
            rule_id="S3-001",
            resource_id="bucket-b",
            title="Bucket is public",
            severity=Severity.HIGH,
            cis_control="2.1.5",
            remediation="Block public access.",
            evidence={"public": True},
            detected_at=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
        ),
        Finding(
            finding_id=uuid4(),
            fingerprint=generate_fingerprint(
                "IAM-001", resources[2].resource_type, resources[2].resource_id
            ),
            scan_id=scan_id,
            rule_id="IAM-001",
            resource_id="role-a",
            title="Role trust is too broad",
            severity=Severity.CRITICAL,
            remediation="Limit trusted principals.",
            evidence={"principal": "*"},
            detected_at=datetime(2026, 1, 1, 0, 3, tzinfo=UTC),
        ),
    ]

    assert len(scan.collector_results) == 2
    assert scan.collector_results[1].errors[0].operation == "GetRole"
    assert len(resources) == 3
    assert len(rules) == 2
    assert len(findings) == 3
    assert "resource_type" not in Finding.model_fields

    for finding in findings:
        resource = resources_by_identity[(finding.scan_id, finding.resource_id)]
        rule = rules_by_id[finding.rule_id]
        assert finding.scan_id == scan.scan_id
        assert resource.scan_id == scan.scan_id
        assert resource.resource_type == rule.resource_type
        assert finding.fingerprint == generate_fingerprint(
            rule.rule_id, resource.resource_type, resource.resource_id
        )

    assert sum(finding.rule_id == "S3-001" for finding in findings) == 2

    later_scan_id = uuid4()
    later_resource = Resource(
        scan_id=later_scan_id,
        resource_id="bucket-a",
        resource_type="s3_bucket",
        region="us-east-1",
    )
    assert generate_fingerprint(
        "S3-001", later_resource.resource_type, later_resource.resource_id
    ) == findings[0].fingerprint

    assert Scan.model_validate_json(scan.model_dump_json()) == scan
    assert [
        Resource.model_validate_json(resource.model_dump_json())
        for resource in resources
    ] == resources
    assert [Rule.model_validate_json(rule.model_dump_json()) for rule in rules] == rules
    assert [
        Finding.model_validate_json(finding.model_dump_json()) for finding in findings
    ] == findings
