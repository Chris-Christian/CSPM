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

### LocalStack connectivity

Phase 3 currently supports LocalStack only. Copy `.env.example` to `.env`, replace
`LOCALSTACK_AUTH_TOKEN` with your LocalStack auth token, then start the service:

```powershell
Copy-Item .env.example .env
docker compose up -d
uv run cspm connect
```

The Compose service binds to loopback on port 4566 and enables STS only. The
`connect` command calls the read-only STS `GetCallerIdentity` API. The Python
application reads `CSPM_TARGET`, `CSPM_REGION`, and
`CSPM_LOCALSTACK_ENDPOINT_URL` from the process environment; it does not
automatically read `.env`. Set those variables in PowerShell or another
environment manager if you need values other than the defaults. Real AWS clients
are disabled, and explicit LocalStack test credentials are used.

## Tests and lint

```powershell
uv run pytest
uv run ruff check .
```

## Development status

The core model foundation and LocalStack connectivity check are implemented.
**Resource scanning functionality has not yet been implemented.** There are no
resource collectors, scan orchestration, rule evaluation, persistence, reports,
or scan comparison yet. The application does not connect to real AWS accounts.
