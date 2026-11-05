"""Orchestrate one read-only discovery, assessment, and persistence workflow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cspm.aws.connectivity import verify_connectivity
from cspm.collectors import DiscoveryEngine
from cspm.config import CSPMConfig, load_config
from cspm.models.collector import CollectorResult
from cspm.models.enums import CollectorStatus, ScanStatus, Severity, TargetType
from cspm.models.finding import Finding
from cspm.models.resource import Resource
from cspm.models.scan import Scan
from cspm.persistence import ScanRepository
from cspm.rules import AssessmentEngine, EvaluationRecord


class ScanExecutionError(RuntimeError):
    """A scan failed after its lifecycle record was created."""


@dataclass(frozen=True)
class ScanExecutionResult:
    """Persisted scan output and assessment completeness for CLI presentation."""

    scan: Scan
    resources: tuple[Resource, ...]
    findings: tuple[Finding, ...]
    assessment_errors: tuple[EvaluationRecord, ...]

    @property
    def is_complete(self) -> bool:
        """Whether every collector and rule evaluation completed successfully."""
        return all(
            result.status is CollectorStatus.SUCCESS
            for result in self.scan.collector_results
        ) and not self.assessment_errors

    def severity_count(self, severity: Severity) -> int:
        """Count persisted findings at one severity without separate counters."""
        return sum(finding.severity is severity for finding in self.findings)


def _mark_scan_failed_after_interrupt(
    repository: ScanRepository,
    scan_id: UUID,
    target: TargetType,
    region: str,
    started_at: datetime,
    collector_results: list[CollectorResult],
) -> None:
    """Best-effort failure recording that never masks the active interrupt."""
    try:
        failed_scan = Scan(
            scan_id=scan_id,
            target=target,
            region=region,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            status=ScanStatus.FAILED,
            collector_results=collector_results,
        )
        repository.update_scan(failed_scan)
    except BaseException:
        # This catch is limited to the best-effort update while an interrupt is
        # already propagating; no record is created if the original insert rolled back.
        pass


def run_scan(
    repository: ScanRepository, config: CSPMConfig | None = None
) -> ScanExecutionResult:
    """Run and persist a complete scan workflow without mutating AWS resources."""
    supplied_settings = config if config is not None else load_config()
    settings = CSPMConfig.model_validate(supplied_settings.model_dump())
    verify_connectivity(settings)
    repository.initialize()

    scan_id = uuid4()
    started_at = datetime.now(UTC)
    running_scan = Scan(
        scan_id=scan_id,
        target=settings.target,
        region=settings.region,
        started_at=started_at,
        status=ScanStatus.RUNNING,
    )
    collector_results: list[CollectorResult] = []
    resources: list[Resource] = []
    scan_created = False
    stage = "scan creation"
    try:
        repository.create_scan(running_scan)
        scan_created = True

        stage = "resource discovery"
        discovery = DiscoveryEngine(settings).discover(scan_id)
        resources = discovery.resources
        collector_results = discovery.collector_results

        stage = "resource persistence"
        repository.save_resources(resources)

        stage = "rule registration"
        engine = AssessmentEngine(config=settings)
        engine.load_rules(repository)

        stage = "rule assessment"
        assessment = engine.evaluate(resources)

        stage = "assessment persistence"
        repository.persist_assessment(scan_id, assessment)

        stage = "scan completion"
        completed_scan = Scan(
            scan_id=scan_id,
            target=settings.target,
            region=settings.region,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            status=ScanStatus.COMPLETED,
            collector_results=collector_results,
        )
        repository.update_scan(completed_scan)
    except KeyboardInterrupt:
        _mark_scan_failed_after_interrupt(
            repository,
            scan_id,
            settings.target,
            settings.region,
            started_at,
            collector_results,
        )
        raise
    except Exception as exc:
        if not scan_created:
            raise
        failed_scan = Scan(
            scan_id=scan_id,
            target=settings.target,
            region=settings.region,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            status=ScanStatus.FAILED,
            collector_results=collector_results,
        )
        try:
            repository.update_scan(failed_scan)
        except Exception as status_error:
            raise ScanExecutionError(
                f"Scan {scan_id} failed during {stage}; its failed state could not "
                f"be recorded ({type(status_error).__name__})."
            ) from exc
        raise ScanExecutionError(
            f"Scan {scan_id} failed during {stage} ({type(exc).__name__}); "
            "the failed state was recorded."
        ) from exc

    return ScanExecutionResult(
        scan=completed_scan,
        resources=tuple(resources),
        findings=assessment.findings,
        assessment_errors=assessment.errors,
    )
