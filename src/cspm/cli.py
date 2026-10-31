"""Command line interface for CSPM."""

import click
from rich.console import Console

from cspm.aws.client_factory import UnsupportedTargetError
from cspm.aws.connectivity import ConnectivityError, verify_connectivity
from cspm.config import ConfigurationError, load_config


@click.group()
@click.version_option(package_name="cspm")
def main() -> None:
    """Read-only AWS Cloud Security Posture Manager."""


@main.command()
def connect() -> None:
    """Verify connectivity to the configured LocalStack STS service."""
    try:
        result = verify_connectivity(load_config())
    except (ConfigurationError, UnsupportedTargetError, ConnectivityError) as exc:
        raise click.ClickException(str(exc)) from None

    Console().print(
        "[green]LocalStack connectivity successful[/green] "
        f"(account: {result.account}, ARN: {result.arn})"
    )


if __name__ == "__main__":
    main()
