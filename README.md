# CSPM

A read-only AWS Cloud Security Posture Manager (CSPM) university project. The planned system will discover S3 buckets, IAM roles and policies, and EC2 security groups; evaluate configurations against modular rules; record scan history in SQLite; generate JSON, HTML, and Markdown reports; and compare scans for configuration drift. It will operate through a CLI and will not modify AWS resources.

## Technology stack

- Python 3.13.2, managed with uv
- Click and Rich for the CLI and terminal output
- Boto3 for planned AWS integration
- SQLite for planned scan history
- Pydantic for data validation
- Jinja2 for planned HTML reports
- pytest and Ruff for development

## Installation (Windows PowerShell)

Install Python 3.13.2 separately if needed, then install uv. From the project directory, run:

```powershell
uv sync --all-groups
```

This creates the project environment and installs runtime and development dependencies from `uv.lock`.

## Usage

Show the CLI help:

```powershell
uv run cspm --help
```

## Tests and lint

```powershell
uv run pytest
uv run ruff check .
```

## Development status

Project foundation only. **Scanning functionality has not yet been implemented.** The CLI currently provides help and version output; it does not connect to AWS, scan resources, evaluate rules, persist history, generate reports, or compare scans.
