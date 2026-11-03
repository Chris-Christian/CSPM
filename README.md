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

The Compose service binds to loopback on port 4566 and enables STS, S3, IAM,
and EC2. The `connect` command calls the read-only STS `GetCallerIdentity` API.
The Python
application reads `CSPM_TARGET`, `CSPM_REGION`, and
`CSPM_LOCALSTACK_ENDPOINT_URL` from the process environment; it does not
automatically read `.env`. Set those variables in PowerShell or another
environment manager if you need values other than the defaults. Real AWS clients
are disabled, and explicit LocalStack test credentials are used.

## Resource discovery (Phase 4)

The S3 collector discovers bucket creation time, region, tags, ACL grants,
bucket-level Block Public Access settings, bucket policies, and policy public
status. The IAM collector discovers roles, trust policies, attached managed
policies, inline role policies, customer-managed policies, policy documents,
permissions boundaries, and tags. IAM resources use the documented `global`
region value because IAM is a global service. The EC2 collector discovers
security groups, ingress and egress permissions, IPv4/IPv6 ranges, referenced
groups, VPC/owner information, and tags.

Production collectors only call read/list/describe/get APIs. They preserve
incomplete enrichment as collector errors and mark coverage partial; a failed
primary inventory request is reported as failed. Discovery returns resources
and per-collector results in memory. Scan lifecycle management, evaluation,
findings, persistence, and reports are not part of this phase.

After changing Compose services, recreate LocalStack from PowerShell:

```powershell
docker compose up -d --no-build --pull never
```

Run the unit suite and the real LocalStack discovery integration test:

```powershell
uv run pytest tests/unit -v
uv run pytest -m integration -v
```

Integration tests require a healthy LocalStack instance with STS, S3, IAM, and
EC2 enabled. They create uniquely named synthetic resources and clean up only
those resources. They skip only if the loopback LocalStack endpoint cannot be
reached; a reachable endpoint with a missing service fails the test. The
current discovery uses explicit per-resource AWS API calls and does not yet
provide cross-service transactionality; AWS IAM policy versions and some S3
configuration APIs can vary in emulation fidelity across LocalStack releases.

## Tests and lint

```powershell
uv run pytest
uv run ruff check .
```

## Development status

The core models, LocalStack connectivity check, and Phase 4 read-only resource
discovery are implemented. Rule evaluation, findings generation, persistence,
reports, and scan comparison remain future work. The application does not
connect to real AWS accounts.
