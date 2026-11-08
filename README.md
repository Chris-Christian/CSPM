# CSPM - Cloud Security Posture Manager

A Python-based Cloud Security Posture Management tool that discovers AWS resources, identifies security misconfigurations, and generates actionable security assessment reports.

CSPM currently assesses Amazon S3, AWS IAM, and EC2 Security Groups through an extensible rule engine.

## Features

- **Cloud Discovery:** Collects configuration and security metadata from S3, IAM, and EC2.
- **Security Assessment:** Evaluates resources against built-in security rules.
- **Risk Classification:** Categorizes findings as Critical, High, Medium, or Low.
- **Evidence-Based Findings:** Provides affected resources, supporting evidence, and remediation guidance.
- **Scan Persistence:** Stores scan results and findings in SQLite.
- **Reporting:** Generates JSON, HTML, and Markdown reports.
- **Coverage Tracking:** Identifies incomplete discovery and assessment results instead of incorrectly treating them as clean assessments.

## Security Rules

| Rule ID | Description                                           | Severity |
| ------- | ----------------------------------------------------- | -------- |
| S3-001  | Public bucket policy without bucket-level restriction | High     |
| S3-002  | Public ACL grants not ignored                         | High     |
| S3-003  | Incomplete S3 Block Public Access configuration       | Medium   |
| IAM-001 | Broad IAM permissions and wildcard actions            | High     |
| IAM-002 | Unconditional wildcard role trust                     | Critical |
| EC2-001 | Sensitive IPv4 ingress exposed to the internet        | High     |
| EC2-002 | Sensitive IPv6 ingress exposed to the internet        | High     |

EC2 sensitive ports are configurable through environment variables. TCP defaults include SSH, Telnet, SMB, database, and other commonly sensitive ports.

## Technology Stack

- Python 3.13+
- Boto3
- Pydantic
- Click
- SQLite
- Jinja2
- LocalStack
- uv
- Pytest and Ruff

## Prerequisites

- Python 3.13 or later
- [uv](https://docs.astral.sh/uv/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- LocalStack authentication token, where required by your LocalStack edition

## Installation

Clone the repository:

```bash
git clone https://github.com/Chris-Christian/CSPM.git
cd CSPM
```

Install dependencies:

```bash
uv sync --locked
```

Configure the environment:

```shell
cp .env.example .env
```

Update `.env` with the required LocalStack authentication token. Keep this file private and never commit it.

## Running CSPM

### 1. Start LocalStack

```bash
docker compose up -d
```

LocalStack provides an isolated AWS-compatible environment for testing CSPM.

### 2. Verify connectivity

```bash
uv run --locked cspm connect
```

Checks connectivity with LocalStack through AWS STS.

### 3. Run a security scan

```bash
uv run --locked cspm scan --database .local/cspm.sqlite3
```

Discovers resources, evaluates security rules, and persists the results in SQLite.

### 4. Generate reports

Replace `<SCAN_ID>` with the UUID returned by the scan command.

```bash
uv run --locked cspm report <SCAN_ID> --database .local/cspm.sqlite3 --format all
```

Supported formats:

- `json`
- `html`
- `markdown`
- `all`

Reports are generated under:

```text
reports/
└── <SCAN_ID>/
    ├── findings.json
    ├── report.html
    └── report.md
```

Open `report.html` in your browser to view the assessment.

Existing report files are not overwritten.

## Configuration

| Variable                       | Description                      |
| ------------------------------ | -------------------------------- |
| `CSPM_TARGET`                  | Assessment target                |
| `CSPM_REGION`                  | AWS region                       |
| `CSPM_LOCALSTACK_ENDPOINT_URL` | LocalStack endpoint              |
| `CSPM_SENSITIVE_PORTS`         | Configurable TCP sensitive ports |
| `CSPM_SENSITIVE_UDP_PORTS`     | Configurable UDP sensitive ports |

See `.env.example` for the available configuration and default values.

## Security Considerations and Limitations

- The current validated execution target is LocalStack; live AWS scanning is not supported by the current client configuration.
- Production collectors use read-only cloud operations.
- The tool does not automatically remediate findings.
- Account-level S3 Block Public Access settings are not currently collected.
- IAM policy conditions are not fully simulated.
- Sensitive-port checks are configurable detection rules, not a complete network security assessment.
- Incomplete collector or assessment coverage must not be interpreted as a clean assessment.
- Historical drift comparison is not currently implemented.

## License

Distributed under the [MIT License](LICENSE).
