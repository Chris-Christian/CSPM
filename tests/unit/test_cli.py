from unittest.mock import patch

from click.testing import CliRunner

from cspm.aws.connectivity import ConnectivityError, ConnectivityResult
from cspm.cli import main


def test_cli_help_displays_application_description() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Read-only AWS Cloud Security Posture Manager." in result.output


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
