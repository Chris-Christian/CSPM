# CSPM — Cloud Security Posture Manager

A Python-based CLI tool for discovering cloud resources, identifying security misconfigurations, and generating security assessment reports.

CSPM currently supports **LocalStack** for local testing and **Amazon Web Services (AWS)** for real cloud assessments.

## Features

- Read-only discovery of S3 buckets, IAM roles and policies, and EC2 security groups.
- Automated security checks using seven built-in detection rules.
- Assessment coverage and error tracking.
- SQLite-based scan history and persistence.
- JSON, Markdown, and HTML reports.
- Support for LocalStack and real AWS environments.
- AWS account identity verification before scanning.

## Security Rules

| Rule ID | Description                                                                | Severity |
| ------- | -------------------------------------------------------------------------- | -------- |
| S3-001  | Public bucket policy without bucket-level RestrictPublicBuckets protection | HIGH     |
| S3-002  | Public ACL grants not ignored by IgnorePublicAcls                          | HIGH     |
| S3-003  | Incomplete S3 Block Public Access configuration                            | MEDIUM   |
| IAM-001 | Broad IAM permissions and wildcard actions                                 | HIGH     |
| IAM-002 | Unconditional wildcard principal in IAM trust policy                       | CRITICAL |
| EC2-001 | IPv4 internet-wide ingress on sensitive ports                              | HIGH     |
| EC2-002 | IPv6 internet-wide ingress on sensitive ports                              | HIGH     |

## Technology Stack

- Python 3.13+
- Boto3
- Pydantic
- Click
- SQLite
- Jinja2
- Docker and LocalStack
- pytest and Ruff

## Prerequisites

- Python 3.13 or later
- [uv](https://docs.astral.sh/uv/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (for LocalStack)
- AWS CLI (for real AWS assessments)

## Installation

Clone the repository:

```shell
git clone https://github.com/Chris-Christian/CSPM.git
cd CSPM
```

Install dependencies:

```shell
uv sync --locked
```

Copy the example environment file:

```shell
cp .env.example .env
```

Configure the LocalStack authentication token in `.env` if required by your LocalStack setup.

## Usage

CSPM supports two targets: LocalStack and AWS. Select the target explicitly before running commands.

### 1. LocalStack

Start LocalStack:

```shell
docker compose up -d
```

Check container health:

```shell
docker compose ps
```

- Select LocalStack
  - for Windows:

    ```powershell
    $env:CSPM_TARGET = "localstack"
    ```

  - for Linux:

    ```shell
    CSPM_TARGET="localstack"
    ```

Check connectivity:

```shell
uv run --locked cspm connect
```

Run a scan:

```shell
uv run --locked cspm scan --database .local/cspm.sqlite3
```

### 2. Amazon Web Services

CSPM can perform read-only assessments against an actual AWS account.

#### Configure AWS credentials

Create a dedicated IAM identity with only the permissions required by CSPM. Do not use root account credentials or administrator access.

Configure a named AWS CLI profile:

```shell
aws configure --profile cspm-readonly
```

Provide the access key, secret access key, default region, and output format when prompted.

Verify the configured identity:

```shell
aws sts get-caller-identity --profile cspm-readonly
```

Confirm that the returned account ID is the intended AWS account.

#### Configure CSPM

- Set the AWS profile, target, and region
  - for Windows:

    ```powershell
    $env:AWS_PROFILE = "cspm-readonly"
    $env:CSPM_TARGET = "aws"
    $env:CSPM_REGION = "ap-south-1"
    ```

  - for Linux:

    ```shell
    AWS_PROFILE="cspm-readonly"
    CSPM_TARGET="aws"
    CSPM_REGION="ap-south-1"
    ```

- Remove any LocalStack endpoint override from the current
  - PowerShell session:

    ```powershell
    Remove-Item Env:CSPM_LOCALSTACK_ENDPOINT_URL -ErrorAction SilentlyContinue
    ```

  - shell session:

    ```shell
    unset CSPM_LOCALSTACK_ENDPOINT_URL
    ```

Verify AWS connectivity:

```powershell
uv run --locked cspm connect
```

CSPM displays the AWS account ID and region before proceeding.

Run a scan:

```powershell
uv run --locked cspm scan --database .local/cspm-aws.sqlite3
```

The configured region determines the EC2 security groups discovered. IAM inventory is account-wide, and S3 bucket inventory spans the account's buckets.

### 3. Generate Reports

Use the scan ID printed after a successful scan:

```powershell
uv run --locked cspm report SCAN_ID --database .local/cspm-aws.sqlite3 --format all
```

Replace `SCAN_ID` with the actual scan identifier.

CSPM generates:

- `findings.json`
- `report.md`
- `report.html`

Reports contain scan information, discovered resources, findings, severity classifications, evidence, remediation guidance, and assessment coverage.

## Configuration

The following environment variables control the target and AWS configuration:

| Variable                       | Description                                          |
| ------------------------------ | ---------------------------------------------------- |
| `CSPM_TARGET`                  | Assessment target: `localstack` or `aws`             |
| `CSPM_REGION`                  | AWS or LocalStack region                             |
| `CSPM_LOCALSTACK_ENDPOINT_URL` | LocalStack endpoint URL; must use a loopback address |
| `AWS_PROFILE`                  | Named AWS CLI profile used for AWS authentication    |

LocalStack is the default target. AWS must be explicitly selected.

AWS credentials are resolved through Boto3's standard credential provider chain. Do not store AWS credentials in project configuration files.

## Troubleshooting

### AWS variables remain set when running LocalStack tests

PowerShell environment variables persist within the current session. Switch back to LocalStack before running its integration tests:

```powershell
$env:CSPM_TARGET = "localstack"
$env:CSPM_REGION = "us-east-1"
Remove-Item Env:AWS_PROFILE -ErrorAction SilentlyContinue
Remove-Item Env:CSPM_LOCALSTACK_ENDPOINT_URL -ErrorAction SilentlyContinue
```

Shell environment variables persist within the current session. Switch back to LocalStack before its integration test:

```shell
export CSPM_TARGET="localstack"
export CSPM_REGION="us-east-1"
unset AWS_PROFILE
unset CSPM_LOCALSTACK_ENDPOINT_URL
```

### LocalStack is unavailable

Ensure Docker Desktop is running:

```shell
docker compose up -d
docker compose ps
```

Wait until the LocalStack container reports a healthy status.

### S3 IllegalLocationConstraintException during LocalStack integration tests

- Use `us-east-1` for the LocalStack integration-test environment:
  - For Windows:

  ```powershell
  $env:CSPM_TARGET = "localstack"
  $env:CSPM_REGION = "us-east-1"
  ```

  - For Linux:

  ```shell
  CSPM_TARGET="localstack"
  CSPM_REGION="us-east-1"
  ```

This avoids creating test buckets against a regional S3 endpoint without a matching location constraint.

### AWS connectivity or AccessDenied errors

Verify the configured profile:

```shell
aws sts get-caller-identity --profile cspm-readonly
```

Check that the profile is selected and that the IAM identity has the required read permissions.

### Incomplete assessment coverage

Review the assessment errors in the CLI output and generated report. Incomplete coverage must not be interpreted as a clean security assessment.

## Testing

Start Docker Desktop and LocalStack before running the full test suite.

- Select the LocalStack target:
  - For Windows:

  ```powershell
  $env:CSPM_TARGET = "localstack"
  $env:CSPM_REGION = "us-east-1"
  Remove-Item Env:AWS_PROFILE -ErrorAction SilentlyContinue
  Remove-Item Env:CSPM_LOCALSTACK_ENDPOINT_URL -ErrorAction SilentlyContinue
  ```

  - For Linux:

  ```shell
  export CSPM_TARGET="localstack"
  export CSPM_REGION="us-east-1"
  unset AWS_PROFILE
  unset CSPM_LOCALSTACK_ENDPOINT_URL
  ```

Run tests:

```shell
uv run --locked pytest -q
```

Run Ruff:

```shell
uv run --locked ruff check .
```

The integration tests use LocalStack and must not be run with the AWS target selected.

## Security Considerations and Limitations

- Production collectors use read-only AWS API operations.
- CSPM does not create, modify, or remediate AWS resources during assessments.
- AWS credentials must be configured outside the project.
- LocalStack endpoints are restricted to loopback addresses.
- EC2 security group discovery covers one configured region per scan.
- Account-level S3 Block Public Access configuration is not currently collected.
- IAM policy conditions are not fully simulated.
- S3 checks evaluate collected bucket-level configuration; they do not constitute a complete effective-access analysis.
- Assessment results depend on the resources and permissions available to the configured identity.
- A scan with incomplete coverage must not be considered a clean assessment.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
