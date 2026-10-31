from click.testing import CliRunner

from cspm.cli import main


def test_cli_help_displays_application_description() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Read-only AWS Cloud Security Posture Manager." in result.output
