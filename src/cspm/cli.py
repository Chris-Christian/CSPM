"""Command line interface for CSPM."""

import click


@click.group()
@click.version_option(package_name="cspm")
def main() -> None:
    """Read-only AWS Cloud Security Posture Manager."""


if __name__ == "__main__":
    main()
