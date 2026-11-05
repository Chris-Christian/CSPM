"""Unit tests for the SQLite ScanRepository."""

import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from cspm.config import load_config
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
)
from cspm.persistence import (
    RepositoryDataError,
    RepositoryIntegrityError,
    RepositoryNotFoundError,
    RepositorySchemaError,
    RepositorySerializationError,
    ScanRepository,
)
from cspm.rules import (
    AssessmentEngine,
    AssessmentResult,
    EvaluationRecord,
    EvaluationStatus,
)


@pytest.fixture
def repository(tmp_path) -> ScanRepository:
    result = ScanRepository(tmp_path / "cspm.sqlite3")
    result.initialize()
    return result


def make_scan(
    *,
    scan_id=None,
    status: ScanStatus = ScanStatus.RUNNING,
    collector_results: list[CollectorResult] | None = None,
) -> Scan:
    return Scan(
        scan_id=scan_id or uuid4(),
        target=TargetType.LOCALSTACK,
        region="us-east-1",
        started_at=datetime(
            2026, 10, 1, 12, tzinfo=timezone(timedelta(hours=5, minutes=30))
        ),
        completed_at=(
            datetime(2026, 10, 1, 12, 30, tzinfo=UTC)
            if status is not ScanStatus.RUNNING
            else None
        ),
        status=status,
        collector_results=collector_results or [],
    )


def make_resource(scan_id, resource_id: str = "bucket-1", **overrides) -> Resource:
    values = {
        "scan_id": scan_id,
        "resource_id": resource_id,
        "resource_type": "s3_bucket",
        "region": "us-east-1",
        "raw_metadata": {"nested": {"unicode": "雪☃", "values": [1, True, None]}},
        "tags": {"environment": "test"},
    }
    values.update(overrides)
    return Resource(**values)


def make_rule(rule_id: str = "S3-001", **overrides) -> Rule:
    values = {
        "rule_id": rule_id,
        "title": "Public bucket check",
        "resource_type": "s3_bucket",
        "severity": Severity.HIGH,
        "remediation_text": "Remove unintended public access.",
    }
    values.update(overrides)
    return Rule(**values)


def make_finding(scan_id, resource_id: str = "bucket-1", **overrides) -> Finding:
    values = {
        "finding_id": uuid4(),
        "fingerprint": "v1:" + "a" * 64,
        "scan_id": scan_id,
        "rule_id": "S3-001",
        "resource_id": resource_id,
        "title": "Public bucket policy",
        "severity": Severity.HIGH,
        "remediation": "Restrict the bucket policy.",
        "evidence": {"principal": "*", "nested": ["雪", 1, False]},
        "detected_at": datetime(2026, 10, 1, 15, tzinfo=timezone(timedelta(hours=3))),
    }
    values.update(overrides)
    return Finding(**values)


def test_initialize_is_idempotent_and_creates_exactly_four_tables(repository) -> None:
    repository.initialize()
    with sqlite3.connect(repository.db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        resource_pk = connection.execute("PRAGMA table_info(resources)").fetchall()
        finding_fks = connection.execute("PRAGMA foreign_key_list(findings)").fetchall()

    assert tables == {"scans", "resources", "findings", "rules"}
    assert {"idx_findings_scan_id", "idx_findings_rule_resource"} <= indexes
    assert [(row[1], row[5]) for row in resource_pk if row[5]] == [
        ("scan_id", 1),
        ("resource_id", 2),
    ]
    assert len({row[0] for row in finding_fks}) == 3


def test_initialize_rejects_scans_table_missing_assessment_errors_without_data_loss(
    repository,
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    with sqlite3.connect(repository.db_path) as connection:
        connection.execute("ALTER TABLE scans DROP COLUMN assessment_errors_json")

    with pytest.raises(
        RepositorySchemaError, match="table scans.*assessment_errors_json"
    ):
        ScanRepository(repository.db_path).initialize()

    with sqlite3.connect(repository.db_path) as connection:
        assert connection.execute(
            "SELECT scan_id FROM scans WHERE scan_id = ?", (str(scan.scan_id),)
        ).fetchone() == (str(scan.scan_id),)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
    assert "assessment_errors_json" not in columns


def test_initialize_rejects_resources_primary_key_mismatch_without_data_loss(
    repository,
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    resource = make_resource(scan.scan_id)
    with sqlite3.connect(repository.db_path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE resources")
        connection.execute(
            """CREATE TABLE resources (
                scan_id TEXT NOT NULL,
                resource_id TEXT NOT NULL PRIMARY KEY,
                resource_type TEXT NOT NULL,
                region TEXT NOT NULL,
                raw_metadata_json TEXT NOT NULL,
                tags_json TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO resources VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(resource.scan_id),
                resource.resource_id,
                resource.resource_type,
                resource.region,
                "{}",
                "{}",
            ),
        )

    with pytest.raises(RepositorySchemaError, match="table resources.*primary key"):
        ScanRepository(repository.db_path).initialize()

    with sqlite3.connect(repository.db_path) as connection:
        assert connection.execute(
            "SELECT resource_id FROM resources WHERE resource_id = ?",
            (resource.resource_id,),
        ).fetchone() == (resource.resource_id,)


def test_initialize_rejects_findings_missing_composite_resource_foreign_key(
    repository,
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    repository.save_resources([make_resource(scan.scan_id)])
    repository.sync_rules([make_rule()])
    finding = make_finding(scan.scan_id)
    repository.save_findings([finding])

    with sqlite3.connect(repository.db_path) as connection:
        existing = connection.execute(
            "SELECT * FROM findings WHERE finding_id = ?",
            (str(finding.finding_id),),
        ).fetchone()
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE findings")
        connection.execute(
            """CREATE TABLE findings (
                finding_id TEXT PRIMARY KEY NOT NULL,
                fingerprint TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
                cis_control TEXT,
                remediation TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id),
                FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
            )"""
        )
        connection.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            tuple(existing),
        )

    with pytest.raises(RepositorySchemaError, match="table findings foreign keys"):
        ScanRepository(repository.db_path).initialize()

    with sqlite3.connect(repository.db_path) as connection:
        assert connection.execute(
            "SELECT finding_id FROM findings WHERE finding_id = ?",
            (str(finding.finding_id),),
        ).fetchone() == (str(finding.finding_id),)


def test_initialize_rejects_required_index_with_wrong_columns_without_data_loss(
    repository,
) -> None:
    repository.initialize()
    with sqlite3.connect(repository.db_path) as connection:
        connection.execute("DROP INDEX idx_findings_rule_resource")
        connection.execute(
            "CREATE INDEX idx_findings_rule_resource ON findings (resource_id, rule_id)"
        )

    with pytest.raises(
        RepositorySchemaError,
        match="idx_findings_rule_resource columns mismatch",
    ):
        ScanRepository(repository.db_path).initialize()

    with sqlite3.connect(repository.db_path) as connection:
        columns = tuple(
            row[2]
            for row in connection.execute(
                "PRAGMA index_info(idx_findings_rule_resource)"
            )
        )
    assert columns == ("resource_id", "rule_id")


def test_scan_round_trip_and_lifecycle_update_preserve_status(repository) -> None:
    partial = CollectorResult(
        collector_name="s3",
        status=CollectorStatus.PARTIAL,
        resources_discovered=1,
        errors=[CollectorError(error_code="GetTags", message="Tag lookup failed")],
    )
    scan = make_scan(collector_results=[partial])
    repository.create_scan(scan)

    retrieved = repository.get_scan(scan.scan_id)
    assert retrieved == scan
    assert retrieved.started_at.utcoffset() == timedelta(0)
    assert retrieved.collector_results[0].status is CollectorStatus.PARTIAL
    assert retrieved.collector_results[0].errors[0].message == "Tag lookup failed"
    assert repository.get_assessment_errors(scan.scan_id) is None

    completed = Scan.model_validate(
        {
            **scan.model_dump(),
            "status": ScanStatus.COMPLETED,
            "completed_at": datetime(2026, 10, 1, 18, tzinfo=UTC),
        }
    )
    repository.update_scan(completed)
    updated = repository.get_scan(scan.scan_id)
    assert updated.status is ScanStatus.COMPLETED
    assert updated.collector_results == [partial]


def test_scan_duplicate_and_missing_update_are_reported(repository) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    with pytest.raises(RepositoryIntegrityError, match="scan already exists"):
        repository.create_scan(scan)
    with pytest.raises(RepositoryNotFoundError, match="scan does not exist"):
        repository.update_scan(make_scan())
    assert repository.get_scan(scan.scan_id) == scan


def test_resource_round_trip_composite_identity_and_duplicate(repository) -> None:
    first_scan = make_scan()
    second_scan = make_scan()
    repository.create_scan(first_scan)
    repository.create_scan(second_scan)
    first = make_resource(first_scan.scan_id)
    same_resource_id_other_scan = make_resource(second_scan.scan_id)
    repository.save_resources([first, same_resource_id_other_scan])

    assert repository.get_resources(first_scan.scan_id) == [first]
    assert repository.get_resources(second_scan.scan_id) == [
        same_resource_id_other_scan
    ]
    assert (
        repository.get_resources(first_scan.scan_id)[0].raw_metadata["nested"][
            "unicode"
        ]
        == "雪☃"
    )
    with pytest.raises(RepositoryIntegrityError, match="resource identity"):
        repository.save_resources([first])


def test_resource_foreign_key_is_enforced_on_each_repository_connection(
    repository,
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    with pytest.raises(RepositoryIntegrityError, match="scan is missing"):
        repository.save_resources(
            [make_resource(uuid4(), "invalid-1"), make_resource(scan.scan_id, "valid")]
        )
    assert repository.get_resources(scan.scan_id) == []


def test_resource_batch_failure_rolls_back_and_connection_closes(
    repository, tmp_path
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    valid = make_resource(scan.scan_id, "valid")
    invalid = make_resource(uuid4(), "invalid")

    with pytest.raises(RepositoryIntegrityError):
        repository.save_resources([valid, invalid])
    assert repository.get_resources(scan.scan_id) == []

    renamed = tmp_path / "renamed.sqlite3"
    repository.db_path.rename(renamed)
    assert renamed.exists()


def test_rule_round_trip_nullable_fields_and_upsert(repository) -> None:
    original = make_rule()
    historical = make_rule("OLD-001")
    repository.sync_rules([original, historical])
    repository.sync_rules([original, historical])
    assert repository.get_rules() == [historical, original]

    updated = make_rule(title="Updated title", severity=Severity.CRITICAL)
    repository.sync_rules([updated])
    assert repository.get_rule("S3-001") == updated
    assert repository.get_rule("OLD-001") == historical
    assert len(repository.get_rules()) == 2

    cis_rule = make_rule(
        "S3-002", cis_control="2.1.1", cis_version="CIS AWS Foundations 5.0"
    )
    repository.sync_rules([cis_rule])
    assert repository.get_rule("S3-002") == cis_rule


def test_finding_round_trip_and_foreign_keys(repository) -> None:
    scan = make_scan()
    resource = make_resource(scan.scan_id)
    rule = make_rule(cis_control="2.1.1", cis_version="CIS v5")
    repository.create_scan(scan)
    repository.save_resources([resource])
    repository.sync_rules([rule])
    finding = make_finding(
        scan.scan_id,
        cis_control="2.1.1",
        evidence={"unicode": "雪", "nested": {"items": [1, "two"]}},
    )
    repository.save_findings([finding])
    assert repository.get_findings(scan.scan_id) == [finding]
    assert repository.get_findings(scan.scan_id)[
        0
    ].detected_at.utcoffset() == timedelta(0)

    invalid_rule = make_finding(scan.scan_id, rule_id="MISSING")
    with pytest.raises(
        RepositoryIntegrityError, match="missing scan, rule, or resource"
    ):
        repository.save_findings([invalid_rule])

    invalid_resource = make_finding(scan.scan_id, resource_id="missing")
    with pytest.raises(
        RepositoryIntegrityError, match="missing scan, rule, or resource"
    ):
        repository.save_findings([invalid_resource])


def test_finding_batch_rolls_back_after_later_foreign_key_failure(repository) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    repository.save_resources([make_resource(scan.scan_id)])
    repository.sync_rules([make_rule()])
    valid = make_finding(scan.scan_id)
    missing_resource = make_finding(scan.scan_id, resource_id="missing")

    with pytest.raises(RepositoryIntegrityError):
        repository.save_findings([valid, missing_resource])
    assert repository.get_findings(scan.scan_id) == []


def test_assessment_error_state_distinguishes_not_run_clean_and_incomplete(
    repository,
) -> None:
    scan = make_scan(status=ScanStatus.COMPLETED)
    resource = make_resource(scan.scan_id)
    rule = make_rule()
    repository.create_scan(scan)
    repository.save_resources([resource])
    repository.sync_rules([rule])

    assert repository.get_assessment_errors(scan.scan_id) is None
    repository.persist_assessment(scan.scan_id, AssessmentResult(()))
    assert repository.get_assessment_errors(scan.scan_id) == ()
    assert repository.get_scan(scan.scan_id).status is ScanStatus.COMPLETED

    finding = make_finding(scan.scan_id)
    error = EvaluationRecord(
        resource_id=resource.resource_id,
        resource_type=resource.resource_type,
        rule_id=rule.rule_id,
        status=EvaluationStatus.ERROR,
        finding=finding,
        error_code="IncompletePolicy",
        message="A policy statement could not be evaluated.",
        error_codes=("IncompletePolicy",),
    )
    result = AssessmentResult((error,))
    assert result.findings == (finding,)
    assert result.errors == (error,)
    repository.persist_assessment(scan.scan_id, result)

    retrieved_errors = repository.get_assessment_errors(scan.scan_id)
    assert retrieved_errors is not None and len(retrieved_errors) == 1
    assert retrieved_errors[0].finding == repository.get_findings(scan.scan_id)[0]
    assert retrieved_errors[0].error_code == "IncompletePolicy"
    assert repository.get_scan(scan.scan_id).status is ScanStatus.COMPLETED


def test_assessment_persistence_failure_rolls_back_findings_and_error_state(
    repository,
) -> None:
    scan = make_scan()
    resource = make_resource(scan.scan_id)
    repository.create_scan(scan)
    repository.save_resources([resource])
    repository.sync_rules([make_rule()])
    good = make_finding(scan.scan_id)
    bad = make_finding(scan.scan_id, resource_id="missing")
    records = (
        EvaluationRecord(
            resource_id=good.resource_id,
            resource_type=resource.resource_type,
            rule_id=good.rule_id,
            status=EvaluationStatus.FINDING,
            finding=good,
        ),
        EvaluationRecord(
            resource_id=bad.resource_id,
            resource_type=resource.resource_type,
            rule_id=bad.rule_id,
            status=EvaluationStatus.FINDING,
            finding=bad,
        ),
    )

    with pytest.raises(RepositoryIntegrityError):
        repository.persist_assessment(scan.scan_id, AssessmentResult(records))
    assert repository.get_findings(scan.scan_id) == []
    assert repository.get_assessment_errors(scan.scan_id) is None


def test_malformed_json_and_corrupted_records_raise_repository_data_errors(
    repository,
) -> None:
    scan = make_scan()
    resource = make_resource(scan.scan_id)
    repository.create_scan(scan)
    repository.save_resources([resource])
    repository.sync_rules([make_rule()])
    finding = make_finding(scan.scan_id)
    repository.save_findings([finding])

    with sqlite3.connect(repository.db_path) as connection:
        connection.execute(
            "UPDATE resources SET raw_metadata_json = '{' WHERE scan_id = ?",
            (str(scan.scan_id),),
        )
    with pytest.raises(RepositoryDataError, match="malformed"):
        repository.get_resources(scan.scan_id)

    with sqlite3.connect(repository.db_path) as connection:
        connection.execute(
            "UPDATE findings SET title = '' WHERE finding_id = ?",
            (str(finding.finding_id),),
        )
    with pytest.raises(RepositoryDataError, match="finding record is invalid"):
        repository.get_findings(scan.scan_id)


def test_assessment_error_json_corruption_is_reported(repository) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    repository.persist_assessment(scan.scan_id, AssessmentResult(()))
    with sqlite3.connect(repository.db_path) as connection:
        connection.execute(
            "UPDATE scans SET assessment_errors_json = '{' WHERE scan_id = ?",
            (str(scan.scan_id),),
        )
    with pytest.raises(RepositoryDataError, match="malformed"):
        repository.get_assessment_errors(scan.scan_id)


def test_deeply_nested_stored_json_raises_repository_error_and_closes_connection(
    repository, tmp_path
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    resource = make_resource(scan.scan_id)
    repository.save_resources([resource])
    deeply_nested = '{"nested":' + "[" * 10_000 + "0" + "]" * 10_000 + "}"
    with sqlite3.connect(repository.db_path) as connection:
        connection.execute(
            "UPDATE resources SET raw_metadata_json = ? WHERE scan_id = ?",
            (deeply_nested, str(scan.scan_id)),
        )
    connection.close()

    with pytest.raises(
        RepositoryDataError, match="resource metadata JSON is malformed"
    ):
        repository.get_resources(scan.scan_id)

    renamed = tmp_path / "after-deep-json-error.sqlite3"
    repository.db_path.rename(renamed)
    assert renamed.exists()


def test_json_serialization_rejects_values_mutated_after_model_validation(
    repository,
) -> None:
    scan = make_scan()
    repository.create_scan(scan)
    resource = make_resource(scan.scan_id)
    resource.raw_metadata["unsupported"] = object()

    with pytest.warns(UserWarning, match="Pydantic serializer warnings"):
        with pytest.raises(RepositorySerializationError, match="model validation"):
            repository.save_resources([resource])
    assert repository.get_resources(scan.scan_id) == []


def test_assessment_rule_sync_does_not_change_evaluation_results(repository) -> None:
    engine = AssessmentEngine(config=load_config({}))
    resource = make_resource(uuid4())
    resource.resource_type = "s3_bucket"
    resource.raw_metadata = {
        "policy": {"status": "present", "document": {"Statement": []}},
        "policy_status": {"status": "present", "is_public": True},
        "public_access_block": {
            "status": "present",
            "configuration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        },
        "acl": {"Grants": []},
    }
    before = engine.evaluate([resource])
    definitions = engine.load_rules(repository)
    engine.load_rules(repository)
    after = engine.evaluate([resource])

    assert len(definitions) == 7
    assert len(repository.get_rules()) == 7
    assert [item.status for item in before.evaluations] == [
        item.status for item in after.evaluations
    ]
    assert [item.rule_id for item in before.findings] == [
        item.rule_id for item in after.findings
    ]


def test_database_path_is_explicit_and_missing_assessment_scan_is_not_found(
    repository,
) -> None:
    with pytest.raises(RepositoryNotFoundError, match="scan does not exist"):
        repository.get_assessment_errors(uuid4())


def test_failed_scan_status_is_preserved(repository) -> None:
    failed = make_scan(status=ScanStatus.FAILED)
    repository.create_scan(failed)
    assert repository.get_scan(failed.scan_id).status is ScanStatus.FAILED


def test_scan_rejects_invalid_enums_before_persistence(repository) -> None:
    with pytest.raises(ValidationError):
        Scan(
            scan_id=uuid4(),
            target="invalid",
            region="us-east-1",
            started_at=datetime.now(UTC),
            status="unknown",
        )
