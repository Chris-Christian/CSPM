from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import uuid4

import pytest

import cspm.scan_service as service
from cspm.collectors.discovery import DiscoveryResult
from cspm.config import CSPMConfig
from cspm.models import (
    CollectorError,
    CollectorResult,
    CollectorStatus,
    Finding,
    Resource,
    Rule,
    ScanStatus,
    Severity,
    TargetType,
)
from cspm.persistence import RepositoryError, ScanRepository
from cspm.rules import AssessmentResult, EvaluationRecord, EvaluationStatus


def _resource(scan_id):
    return Resource(
        scan_id=scan_id,
        resource_id="resource-1",
        resource_type="test_resource",
        region="us-east-1",
    )


def _collector_result(status=CollectorStatus.SUCCESS):
    errors = (
        [
            CollectorError(
                error_code="PartialInventory",
                message="Collector coverage is incomplete.",
                operation="ListResources",
            )
        ]
        if status is not CollectorStatus.SUCCESS
        else []
    )
    return CollectorResult(
        collector_name="test_collector",
        status=status,
        resources_discovered=1,
        errors=errors,
    )


def _install_fakes(
    monkeypatch,
    *,
    collector_status=CollectorStatus.SUCCESS,
    finding=False,
):
    collector_result = _collector_result(collector_status)

    class FakeDiscovery:
        def __init__(self, _config):
            pass

        def discover(self, scan_id):
            return DiscoveryResult(
                resources=[_resource(scan_id)],
                collector_results=[collector_result],
            )

    class FakeAssessmentEngine:
        def __init__(self, *, config):
            self.config = config

        def load_rules(self, repository):
            repository.sync_rules(
                [
                    Rule(
                        rule_id="TEST-001",
                        title="Test rule",
                        resource_type="test_resource",
                        severity=Severity.HIGH,
                        remediation_text="Review the test resource.",
                    )
                ]
            )

        def evaluate(self, resources):
            resource = resources[0]
            if finding:
                confirmed_finding = Finding(
                    finding_id=uuid4(),
                    fingerprint="v1:test-fingerprint",
                    scan_id=resource.scan_id,
                    rule_id="TEST-001",
                    resource_id=resource.resource_id,
                    title="Test rule",
                    severity=Severity.HIGH,
                    remediation="Review the test resource.",
                    detected_at=datetime.now(UTC),
                )
                evaluation = EvaluationRecord(
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    rule_id="TEST-001",
                    status=EvaluationStatus.ERROR,
                    finding=confirmed_finding,
                    error_code="IncompleteEvidence",
                    message="Rule evaluation is incomplete.",
                    error_codes=("IncompleteEvidence",),
                )
            else:
                evaluation = EvaluationRecord(
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    rule_id="TEST-001",
                    status=EvaluationStatus.PASSED,
                )
            return AssessmentResult((evaluation,))

    monkeypatch.setattr(service, "DiscoveryEngine", FakeDiscovery)
    monkeypatch.setattr(service, "AssessmentEngine", FakeAssessmentEngine)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: object())


def test_run_scan_persists_findings_errors_and_partial_coverage(
    tmp_path, monkeypatch
):
    _install_fakes(
        monkeypatch,
        collector_status=CollectorStatus.PARTIAL,
        finding=True,
    )
    repository = ScanRepository(tmp_path / "cspm.sqlite3")

    result = service.run_scan(repository, CSPMConfig(target=TargetType.LOCALSTACK))

    stored_scan = repository.get_scan(result.scan.scan_id)
    assert stored_scan is not None
    assert stored_scan.status is ScanStatus.COMPLETED
    assert stored_scan.collector_results[0].status is CollectorStatus.PARTIAL
    assert result.is_complete is False
    assert len(repository.get_resources(stored_scan.scan_id)) == 1
    assert len(repository.get_findings(stored_scan.scan_id)) == 1
    stored_errors = repository.get_assessment_errors(stored_scan.scan_id)
    assert stored_errors is not None
    assert len(stored_errors) == 1
    assert stored_errors[0].finding is not None


def test_run_scan_success_records_completed_coverage(tmp_path, monkeypatch):
    _install_fakes(monkeypatch)
    repository = ScanRepository(tmp_path / "cspm.sqlite3")

    result = service.run_scan(repository, CSPMConfig())

    assert result.scan.status is ScanStatus.COMPLETED
    assert result.is_complete is True
    assert result.findings == ()
    assert result.assessment_errors == ()
    assert repository.get_assessment_errors(result.scan.scan_id) == ()


def test_run_scan_marks_failed_when_resource_persistence_fails(tmp_path, monkeypatch):
    _install_fakes(monkeypatch)
    repository = ScanRepository(tmp_path / "cspm.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)

    def fail_save(_resources):
        raise RepositoryError("simulated resource persistence failure")

    monkeypatch.setattr(repository, "save_resources", fail_save)

    with pytest.raises(service.ScanExecutionError, match="resource persistence"):
        service.run_scan(repository, CSPMConfig())

    stored_scan = repository.get_scan(scan_id)
    assert stored_scan is not None
    assert stored_scan.status is ScanStatus.FAILED
    assert stored_scan.completed_at is not None
    assert stored_scan.collector_results[0].status is CollectorStatus.SUCCESS


def test_run_scan_connection_failure_creates_no_scan(tmp_path, monkeypatch):
    repository = ScanRepository(tmp_path / "missing" / "cspm.sqlite3")

    def fail_connectivity(_config):
        raise RuntimeError("LocalStack is unavailable")

    monkeypatch.setattr(service, "verify_connectivity", fail_connectivity)

    with pytest.raises(RuntimeError, match="unavailable"):
        service.run_scan(repository, CSPMConfig())

    assert not repository.db_path.exists()


def test_keyboard_interrupt_during_discovery_marks_scan_failed(
    tmp_path, monkeypatch
):
    repository = ScanRepository(tmp_path / "interrupt-discovery.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)

    class InterruptedDiscovery:
        def __init__(self, _config):
            pass

        def discover(self, _scan_id):
            raise KeyboardInterrupt

    monkeypatch.setattr(service, "DiscoveryEngine", InterruptedDiscovery)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)

    with pytest.raises(KeyboardInterrupt):
        service.run_scan(repository, CSPMConfig())

    stored = repository.get_scan(scan_id)
    assert stored is not None
    assert stored.status is ScanStatus.FAILED


def test_keyboard_interrupt_during_assessment_marks_scan_failed(
    tmp_path, monkeypatch
):
    _install_fakes(monkeypatch)
    repository = ScanRepository(tmp_path / "interrupt-assessment.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)

    class InterruptedAssessment:
        def __init__(self, *, config):
            pass

        def load_rules(self, _repository):
            return ()

        def evaluate(self, _resources):
            raise KeyboardInterrupt

    monkeypatch.setattr(service, "AssessmentEngine", InterruptedAssessment)

    with pytest.raises(KeyboardInterrupt):
        service.run_scan(repository, CSPMConfig())

    stored = repository.get_scan(scan_id)
    assert stored is not None
    assert stored.status is ScanStatus.FAILED


@pytest.mark.parametrize(
    "recording_error",
    [
        RepositoryError("could not record failure"),
        KeyboardInterrupt("second interrupt"),
    ],
)
def test_keyboard_interrupt_is_preserved_if_failure_recording_fails(
    tmp_path, monkeypatch, recording_error
):
    repository = ScanRepository(tmp_path / "interrupt-recording.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)

    class InterruptedDiscovery:
        def __init__(self, _config):
            pass

        def discover(self, _scan_id):
            raise KeyboardInterrupt("original cancellation")

    monkeypatch.setattr(service, "DiscoveryEngine", InterruptedDiscovery)
    real_update = repository.update_scan

    def fail_failed_update(scan):
        if scan.status is ScanStatus.FAILED:
            raise recording_error
        return real_update(scan)

    monkeypatch.setattr(repository, "update_scan", fail_failed_update)

    with pytest.raises(KeyboardInterrupt, match="original cancellation"):
        service.run_scan(repository, CSPMConfig())

    stored = repository.get_scan(scan_id)
    assert stored is not None
    assert stored.status is ScanStatus.RUNNING


def test_keyboard_interrupt_before_scan_creation_creates_no_record(
    tmp_path, monkeypatch
):
    repository = ScanRepository(tmp_path / "interrupt-connectivity.sqlite3")

    def interrupt_connectivity(_config):
        raise KeyboardInterrupt

    monkeypatch.setattr(service, "verify_connectivity", interrupt_connectivity)

    with pytest.raises(KeyboardInterrupt):
        service.run_scan(repository, CSPMConfig())

    assert not repository.db_path.exists()


def test_keyboard_interrupt_before_scan_creation_commit_leaves_no_record(
    tmp_path, monkeypatch
):
    repository = ScanRepository(tmp_path / "interrupt-before-commit.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)

    def interrupt_before_commit(_scan):
        raise KeyboardInterrupt("before commit")

    monkeypatch.setattr(repository, "create_scan", interrupt_before_commit)

    with pytest.raises(KeyboardInterrupt, match="before commit"):
        service.run_scan(repository, CSPMConfig())

    assert repository.get_scan(scan_id) is None


def test_keyboard_interrupt_inside_scan_insert_transaction_rolls_back(
    tmp_path, monkeypatch
):
    repository = ScanRepository(tmp_path / "interrupt-inside-transaction.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)
    real_transaction = repository._transaction
    transaction_number = 0

    @contextmanager
    def interrupt_after_insert():
        nonlocal transaction_number
        transaction_number += 1
        with real_transaction() as connection:
            yield connection
            if transaction_number == 2:
                raise KeyboardInterrupt("insert rolled back")

    monkeypatch.setattr(repository, "_transaction", interrupt_after_insert)
    real_create_scan = repository.create_scan
    create_scan_calls = 0

    def count_create_scan(scan):
        nonlocal create_scan_calls
        create_scan_calls += 1
        return real_create_scan(scan)

    monkeypatch.setattr(repository, "create_scan", count_create_scan)

    with pytest.raises(KeyboardInterrupt, match="insert rolled back"):
        service.run_scan(repository, CSPMConfig())

    assert transaction_number == 3  # initialize, insert, failed-state update
    assert create_scan_calls == 1
    assert repository.get_scan(scan_id) is None


def test_keyboard_interrupt_after_scan_creation_commit_marks_scan_failed(
    tmp_path, monkeypatch
):
    repository = ScanRepository(tmp_path / "interrupt-after-commit.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)
    create_scan = repository.create_scan

    def commit_then_interrupt(scan):
        create_scan(scan)
        raise KeyboardInterrupt("after commit")

    monkeypatch.setattr(repository, "create_scan", commit_then_interrupt)

    with pytest.raises(KeyboardInterrupt, match="after commit"):
        service.run_scan(repository, CSPMConfig())

    stored = repository.get_scan(scan_id)
    assert stored is not None
    assert stored.status is ScanStatus.FAILED


def test_run_scan_marks_failed_when_discovery_fails(tmp_path, monkeypatch):
    repository = ScanRepository(tmp_path / "discovery-failure.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(service, "verify_connectivity", lambda _config: None)

    class FailedDiscovery:
        def __init__(self, _config):
            pass

        def discover(self, _scan_id):
            raise RuntimeError("discovery failed")

    monkeypatch.setattr(service, "DiscoveryEngine", FailedDiscovery)
    with pytest.raises(service.ScanExecutionError, match="resource discovery"):
        service.run_scan(repository, CSPMConfig())
    assert repository.get_scan(scan_id).status is ScanStatus.FAILED


@pytest.mark.parametrize("failure_stage", ["registration", "assessment"])
def test_run_scan_marks_failed_for_rule_failures(
    tmp_path, monkeypatch, failure_stage
):
    _install_fakes(monkeypatch)
    repository = ScanRepository(tmp_path / f"{failure_stage}-failure.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)

    class FailedAssessment:
        def __init__(self, *, config):
            pass

        def load_rules(self, _repository):
            if failure_stage == "registration":
                raise RuntimeError("registration failed")

        def evaluate(self, _resources):
            raise RuntimeError("assessment failed")

    monkeypatch.setattr(service, "AssessmentEngine", FailedAssessment)
    expected_stage = (
        "rule registration" if failure_stage == "registration" else "rule assessment"
    )
    with pytest.raises(service.ScanExecutionError, match=expected_stage):
        service.run_scan(repository, CSPMConfig())
    assert repository.get_scan(scan_id).status is ScanStatus.FAILED


def test_assessment_persistence_failure_preserves_unperformed_state(
    tmp_path, monkeypatch
):
    _install_fakes(monkeypatch, finding=True)
    repository = ScanRepository(tmp_path / "assessment-persistence.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    monkeypatch.setattr(
        repository,
        "persist_assessment",
        lambda *_args: (_ for _ in ()).throw(RepositoryError("write failed")),
    )

    with pytest.raises(service.ScanExecutionError, match="assessment persistence"):
        service.run_scan(repository, CSPMConfig())

    stored = repository.get_scan(scan_id)
    assert stored is not None and stored.status is ScanStatus.FAILED
    assert repository.get_assessment_errors(scan_id) is None


def test_final_status_update_failure_retries_failed_status(tmp_path, monkeypatch):
    _install_fakes(monkeypatch)
    repository = ScanRepository(tmp_path / "completion-update.sqlite3")
    scan_id = uuid4()
    monkeypatch.setattr(service, "uuid4", lambda: scan_id)
    real_update = repository.update_scan
    calls = 0

    def fail_completion_once(scan):
        nonlocal calls
        calls += 1
        if calls == 1:
            assert scan.status is ScanStatus.COMPLETED
            raise RepositoryError("completion update failed")
        return real_update(scan)

    monkeypatch.setattr(repository, "update_scan", fail_completion_once)
    with pytest.raises(service.ScanExecutionError, match="scan completion"):
        service.run_scan(repository, CSPMConfig())

    assert calls == 2
    assert repository.get_scan(scan_id).status is ScanStatus.FAILED


def test_scan_uses_one_validated_configuration_snapshot(tmp_path, monkeypatch):
    original = CSPMConfig()
    captured = {}

    class CapturingDiscovery:
        def __init__(self, config):
            captured["discovery_config"] = config

        def discover(self, scan_id):
            return DiscoveryResult(resources=[], collector_results=[])

    class EmptyAssessment:
        def __init__(self, *, config):
            captured["assessment_config"] = config

        def load_rules(self, repository):
            repository.sync_rules([])

        def evaluate(self, _resources):
            return AssessmentResult(())

    def verify_and_mutate(config):
        captured["connectivity_config"] = config
        original.localstack_endpoint_url = "https://sts.amazonaws.com"

    monkeypatch.setattr(service, "verify_connectivity", verify_and_mutate)
    monkeypatch.setattr(service, "DiscoveryEngine", CapturingDiscovery)
    monkeypatch.setattr(service, "AssessmentEngine", EmptyAssessment)

    service.run_scan(ScanRepository(tmp_path / "snapshot.sqlite3"), original)

    endpoint = "http://localhost:4566/"
    assert str(captured["connectivity_config"].localstack_endpoint_url) == endpoint
    assert str(captured["discovery_config"].localstack_endpoint_url) == endpoint
    assert str(captured["assessment_config"].localstack_endpoint_url) == endpoint
    assert original.localstack_endpoint_url == "https://sts.amazonaws.com"
