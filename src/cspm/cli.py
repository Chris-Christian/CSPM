"""Command line interface for CSPM."""

from pathlib import Path
from uuid import UUID

import click
from rich.console import Console
from rich.markup import escape

from cspm.aws.client_factory import UnsupportedTargetError
from cspm.aws.connectivity import (
    ConnectivityError,
    ConnectivityResult,
    verify_connectivity,
)
from cspm.config import ConfigurationError, load_config
from cspm.models.enums import Severity, TargetType
from cspm.persistence import RepositoryError, ScanRepository
from cspm.reporting.exceptions import ReportError
from cspm.reporting.writer import generate_reports
from cspm.scan_service import ScanExecutionError, run_scan


@click.group()
@click.version_option(package_name="cspm")
def main() -> None:
    """Read-only AWS Cloud Security Posture Manager."""


@main.command()
def connect() -> None:
    """Verify STS connectivity and display the configured target account."""
    try:
        config = load_config()
        result = verify_connectivity(config)
    except (ConfigurationError, UnsupportedTargetError, ConnectivityError) as exc:
        raise click.ClickException(str(exc)) from None

    target_name = "AWS" if config.target is TargetType.AWS else "LocalStack"
    Console().print(
        f"[green]{target_name} connectivity successful[/green] "
        f"(account: {escape(result.account)}, region: {escape(config.region)}, "
        f"ARN: {escape(result.arn)})"
    )


@main.command()
@click.option(
    "--database",
    "database_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="SQLite database path for scan history.",
)
def scan(database_path: Path) -> None:
    """Discover resources from the selected target and persist the scan."""
    console = Console()
    try:
        config = load_config()
        console.print("Verifying target account before the read-only scan...")

        def show_verified_account(identity: ConnectivityResult) -> None:
            target_name = "AWS" if config.target is TargetType.AWS else "LocalStack"
            console.print(
                f"Verified {target_name} account {escape(identity.account)} "
                f"in region {escape(config.region)}; starting scan."
            )

        result = run_scan(
            ScanRepository(database_path), config, on_connected=show_verified_account
        )
    except (
        ConfigurationError,
        UnsupportedTargetError,
        ConnectivityError,
        RepositoryError,
        ScanExecutionError,
    ) as exc:
        raise click.ClickException(str(exc)) from None

    completeness = "complete" if result.is_complete else "incomplete"
    console.print(f"Scan ID: {result.scan.scan_id}")
    console.print(f"Scan status: {result.scan.status.value}")
    console.print(f"Assessment coverage: {completeness}")
    console.print(f"Resources discovered: {len(result.resources)}")
    console.print(f"Findings: {len(result.findings)}")
    for severity in Severity:
        console.print(f"  {severity.value}: {result.severity_count(severity)}")
    console.print(f"Assessment errors: {len(result.assessment_errors)}")
    for collector in result.scan.collector_results:
        if collector.status.value != "success":
            name = escape(collector.collector_name)
            console.print(f"Collector {name}: {collector.status.value}")
            for error in collector.errors[:5]:
                operation = error.operation or "collection"
                console.print(f"  {escape(operation)}: {escape(error.message)}")
            if len(collector.errors) > 5:
                console.print(
                    f"  ... {len(collector.errors) - 5} more collector errors"
                )
    for error in result.assessment_errors[:10]:
        rule = error.rule_id or "unmatched rule"
        console.print(
            f"Assessment {escape(rule)} on {escape(error.resource_type)}:"
            f"{escape(error.resource_id)}: "
            f"{escape(error.message or error.error_code or 'incomplete evaluation')}"
        )
    if len(result.assessment_errors) > 10:
        console.print(
            f"... {len(result.assessment_errors) - 10} more assessment errors"
        )
    if not result.is_complete:
        console.print(
            "[yellow]Scan was recorded, but its results are incomplete.[/yellow]"
        )
        raise click.exceptions.Exit(2)
    console.print(
        "[green]Scan completed with complete collector and assessment coverage.[/green]"
    )


def _parse_scan_id(
    _context: click.Context, _parameter: click.Parameter, value: str
) -> UUID:
    """Validate a scan identifier before opening the report database."""
    try:
        return UUID(value)
    except (ValueError, AttributeError):
        raise click.BadParameter("must be a valid UUID") from None


@main.command()
@click.argument("scan_id", callback=_parse_scan_id)
@click.option(
    "--database",
    "database_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="SQLite database containing the persisted scan.",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(("all", "json", "html", "markdown"), case_sensitive=False),
    default="all",
    show_default=True,
    help="Report format to generate.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("reports"),
    show_default=True,
    help="Base directory for per-scan report output.",
)
def report(
    scan_id: UUID,
    database_path: Path,
    report_format: str,
    output_dir: Path,
) -> None:
    """Generate reports from a persisted scan without modifying scan history."""
    if not database_path.is_file():
        raise click.ClickException(
            f"database file does not exist: {database_path}; "
            "provide the path to an existing CSPM database"
        )
    repository = ScanRepository(database_path)
    try:
        repository.validate_schema()
        paths = generate_reports(
            repository,
            scan_id,
            formats=report_format,
            output_dir=output_dir,
        )
    except (RepositoryError, ReportError) as exc:
        raise click.ClickException(str(exc)) from None

    console = Console()
    console.print(f"Reports generated for scan {scan_id}:")
    for report_format, path in paths.items():
        console.print(f"  {report_format}: {path}")


if __name__ == "__main__":
    main()
