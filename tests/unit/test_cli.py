from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from click.testing import CliRunner

from cspm.aws.connectivity import ConnectivityError, ConnectivityResult
from cspm.cli import main
from cspm.config import ConfigurationError
from cspm.models import (
    CollectorError,
    CollectorResult,
    CollectorStatus,
    Scan,
    ScanStatus,
    TargetType,
)
from cspm.reporting.exceptions import ReportNotFoundError, ReportWriteError
from cspm.scan_service import ScanExecutionResult


def _scan_result(*, complete: bool = True) -> ScanExecutionResult:
    collector_status = (
        CollectorStatus.SUCCESS if complete else CollectorStatus.PARTIAL
    )
    scan = Scan(
        scan_id=uuid4(),
        target=TargetType.LOCALSTACK,
        region="us-east-1",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        status=ScanStatus.COMPLETED,
        collector_results=[
            CollectorResult(
                collector_name="s3",
                status=collector_status,
                resources_discovered=0,
                errors=(
                    []
                    if complete
                    else [
                        CollectorError(
                            error_code="EnrichmentFailed",
                            message="Tag enrichment is incomplete.",
                            operation="GetTags",
                        )
                    ]
                ),
            )
        ],
    )
    return ScanExecutionResult(scan, (), (), ())


def test_cli_help_displays_application_description() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Read-only AWS Cloud Security Posture Manager." in result.output
    assert "connect" in result.output
    assert "scan" in result.output
    assert "report" in result.output
    assert "compare" not in result.output


def test_cli_version_displays_project_version() -> None:
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.output


@patch("cspm.cli.verify_connectivity")
def test_connect_command_reports_success(mock_verify: object) -> None:
    mock_verify.return_value = ConnectivityResult(
        connected=True,
        account="000000000000",
        arn="arn:aws:sts::000000000000:assumed-role/test/test",
        user_id="test",
    )

    result = CliRunner().invoke(main, ["connect"])

    assert result.exit_code == 0
    assert "LocalStack connectivity successful" in result.output
    assert "000000000000" in result.output


@patch("cspm.cli.verify_connectivity", side_effect=ConnectivityError("offline"))
def test_connect_command_reports_failure(mock_verify: object) -> None:
    result = CliRunner().invoke(main, ["connect"])

    assert result.exit_code == 1
    assert "offline" in result.output


def test_scan_command_persists_and_summarizes_scan(tmp_path, monkeypatch) -> None:
    expected = _scan_result()
    monkeypatch.setattr("cspm.cli.run_scan", lambda *_args: expected)

    result = CliRunner().invoke(
        main, ["scan", "--database", str(tmp_path / "history.sqlite3")]
    )

    assert result.exit_code == 0
    assert str(expected.scan.scan_id) in result.output
    assert "Resources discovered: 0" in result.output
    assert "Assessment coverage: complete" in result.output


def test_scan_command_returns_distinct_exit_code_for_incomplete_results(
    tmp_path, monkeypatch
) -> None:
    expected = _scan_result(complete=False)
    monkeypatch.setattr("cspm.cli.run_scan", lambda *_args: expected)

    result = CliRunner().invoke(
        main, ["scan", "--database", str(tmp_path / "history.sqlite3")]
    )

    assert result.exit_code == 2
    assert str(expected.scan.scan_id) in result.output
    assert "results are incomplete" in result.output
    assert "GetTags: Tag enrichment is incomplete." in result.output


def test_scan_command_reports_invalid_configuration_without_running(
    tmp_path, monkeypatch
) -> None:
    def fail_config():
        raise ConfigurationError("invalid config")

    monkeypatch.setattr("cspm.cli.load_config", fail_config)
    monkeypatch.setattr("cspm.cli.run_scan", lambda *_args: pytest.fail("must not run"))
    result = CliRunner().invoke(
        main, ["scan", "--database", str(tmp_path / "history.sqlite3")]
    )

    assert result.exit_code == 1
    assert "invalid config" in result.output


def test_scan_command_reports_connection_failure(tmp_path, monkeypatch) -> None:
    def fail_scan(*_args):
        raise ConnectivityError("LocalStack is unavailable")

    monkeypatch.setattr("cspm.cli.run_scan", fail_scan)

    result = CliRunner().invoke(
        main, ["scan", "--database", str(tmp_path / "history.sqlite3")]
    )

    assert result.exit_code == 1
    assert "LocalStack is unavailable" in result.output


@pytest.mark.parametrize("report_format", ["json", "html", "markdown", "all"])
def test_report_command_passes_format_and_custom_output(
    tmp_path, monkeypatch, report_format
) -> None:
    import cspm.cli as cli

    class FakeRepository:
        def validate_schema(self):
            return None

    repository = FakeRepository()
    monkeypatch.setattr(cli, "ScanRepository", lambda _path: repository)
    captured = {}

    def generate(_repository, _scan_id, *, formats, output_dir):
        captured["formats"] = formats
        captured["output_dir"] = output_dir
        return {}

    monkeypatch.setattr(cli, "generate_reports", generate)
    scan_id = uuid4()
    database_path = tmp_path / "history.sqlite3"
    database_path.touch()
    output_dir = tmp_path / "custom-reports"
    result = CliRunner().invoke(
        main,
        [
            "report",
            str(scan_id),
            "--database",
            str(database_path),
            "--format",
            report_format,
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert captured == {"formats": report_format, "output_dir": output_dir}
    assert str(scan_id) in result.output


def test_report_command_defaults_to_all_and_reports_generated_paths(
    tmp_path, monkeypatch
) -> None:
    import cspm.cli as cli

    class FakeRepository:
        def validate_schema(self):
            return None

    monkeypatch.setattr(cli, "ScanRepository", lambda _path: FakeRepository())
    expected_path = tmp_path / "reports" / "findings.json"
    monkeypatch.setattr(
        cli,
        "generate_reports",
        lambda _repository, _scan_id, **kwargs: (
            {"json": expected_path} if kwargs["formats"] == "all" else {}
        ),
    )
    scan_id = uuid4()
    database_path = tmp_path / "history.sqlite3"
    database_path.touch()

    result = CliRunner().invoke(
        main,
        ["report", str(scan_id), "--database", str(database_path)],
    )

    assert result.exit_code == 0
    assert "json:" in result.output
    assert str(expected_path) in result.output.replace("\n", "")


def test_report_command_rejects_invalid_scan_id_before_repository_open(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("cspm.cli.ScanRepository", lambda _path: pytest.fail("opened"))
    result = CliRunner().invoke(
        main,
        ["report", "not-a-uuid", "--database", str(tmp_path / "history.sqlite3")],
    )

    assert result.exit_code == 2
    assert "must be a valid UUID" in result.output


@pytest.mark.parametrize(
    ("error_type", "error_message", "expected_message"),
    [
        (ReportNotFoundError, "scan was not found", "scan was not found"),
        (
            ReportWriteError,
            "existing files are never overwritten",
            "never overwritten",
        ),
    ],
)
def test_report_command_displays_useful_reporting_errors(
    tmp_path, monkeypatch, error_type, error_message, expected_message
) -> None:
    import cspm.cli as cli

    class FakeRepository:
        def validate_schema(self):
            return None

    database_path = tmp_path / "history.sqlite3"
    database_path.touch()
    monkeypatch.setattr(cli, "ScanRepository", lambda _path: FakeRepository())

    def fail_report(*_args, **_kwargs):
        raise error_type(error_message)

    monkeypatch.setattr(cli, "generate_reports", fail_report)
    result = CliRunner().invoke(
        main,
        ["report", str(uuid4()), "--database", str(database_path)],
    )

    assert result.exit_code == 1
    assert expected_message in result.output


def test_report_command_rejects_missing_database_without_creating_it(tmp_path):
    database_path = tmp_path / "missing" / "history.sqlite3"
    result = CliRunner().invoke(
        main,
        ["report", str(uuid4()), "--database", str(database_path)],
    )

    assert result.exit_code == 1
    assert "database file does not exist" in result.output
    assert "existing CSPM database" in result.output
    assert not database_path.exists()
    assert not database_path.parent.exists()


def test_report_command_does_not_initialize_existing_invalid_database(tmp_path):
    database_path = tmp_path / "empty.sqlite3"
    database_path.write_bytes(b"")
    original_contents = database_path.read_bytes()

    result = CliRunner().invoke(
        main,
        ["report", str(uuid4()), "--database", str(database_path)],
    )

    assert result.exit_code == 1
    assert "unsupported SQLite database format" in result.output
    assert database_path.read_bytes() == original_contents


def test_report_command_unknown_scan_does_not_modify_valid_database(tmp_path):
    from cspm.persistence import ScanRepository

    database_path = tmp_path / "history.sqlite3"
    repository = ScanRepository(database_path)
    repository.initialize()
    before = database_path.read_bytes()

    result = CliRunner().invoke(
        main,
        ["report", str(uuid4()), "--database", str(database_path)],
    )

    assert result.exit_code == 1
    assert "was not found" in result.output
    assert database_path.read_bytes() == before


def test_report_validation_and_retrieval_use_read_only_connections(
    tmp_path, monkeypatch
):
    import cspm.persistence as persistence
    from cspm.persistence import ScanRepository

    database_path = tmp_path / "history.sqlite3"
    repository = ScanRepository(database_path)
    repository.initialize()
    scan = _scan_result().scan
    repository.create_scan(scan)
    original_contents = database_path.read_bytes()
    original_connect = persistence.sqlite3.connect
    connection_args = []

    def capture_connect(database, *args, **kwargs):
        connection_args.append((database, kwargs.get("uri", False)))
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(persistence.sqlite3, "connect", capture_connect)
    result = CliRunner().invoke(
        main,
        [
            "report",
            str(scan.scan_id),
            "--database",
            str(database_path),
            "--format",
            "json",
            "--output-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(connection_args) >= 5
    assert all(uri for _database, uri in connection_args)
    assert all("?mode=ro" in database for database, _uri in connection_args)
    assert database_path.read_bytes() == original_contents
    assert all(
        not Path(f"{database_path}{suffix}").exists()
        for suffix in ("-journal", "-wal", "-shm")
    )


def test_report_does_not_create_database_removed_after_cli_path_check(
    tmp_path, monkeypatch
):
    import cspm.persistence as persistence
    from cspm.persistence import ScanRepository

    database_path = tmp_path / "history.sqlite3"
    repository = ScanRepository(database_path)
    repository.initialize()
    original_connect = persistence.sqlite3.connect

    def remove_before_read_only_open(database, *args, **kwargs):
        if kwargs.get("uri"):
            database_path.unlink()
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(
        persistence.sqlite3, "connect", remove_before_read_only_open
    )
    result = CliRunner().invoke(
        main,
        ["report", str(uuid4()), "--database", str(database_path)],
    )

    assert result.exit_code == 1
    assert "SQLite database connection failed" in result.output
    assert not database_path.exists()
    assert all(
        not Path(f"{database_path}{suffix}").exists()
        for suffix in ("-journal", "-wal", "-shm")
    )
