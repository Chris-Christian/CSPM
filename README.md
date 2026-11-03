# CSPM

A read-only AWS Cloud Security Posture Manager (CSPM) university project. The current implementation discovers S3 buckets, IAM roles and policies, and EC2 security groups, then evaluates resources using modular rules. SQLite scan history, reports, and scan comparison remain future work. The project operates through a CLI and does not modify AWS resources during production scans.

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

## Rule assessment (Phase 5)

`AssessmentEngine` evaluates in-memory `Resource` objects with explicitly
registered `BaseRule` instances. It does not make AWS calls, persist results, or
change scan lifecycle state. The default catalogue is constructed explicitly and
ordered by stable rule ID. A rule returns a structured pass, finding, or
incomplete-evidence result; only confirmed violations become `Finding` models.
Evaluation errors remain visible in `AssessmentResult.errors` and are never
converted into passing results or security findings.

The built-in catalogue is:

| Rule ID | Check | Severity | CIS mapping |
| --- | --- | --- | --- |
| S3-001 | Public bucket policy not blocked by `RestrictPublicBuckets` | HIGH | Unset |
| S3-002 | Public ACL grant not ignored by `IgnorePublicAcls` | HIGH | Unset |
| S3-003 | Incomplete bucket-level Block Public Access flags | MEDIUM | Unset |
| IAM-001 | Wildcard actions or broad `Allow` exclusions in a policy document | HIGH | Unset |
| IAM-002 | Unconditional wildcard principal allowed to assume a role | CRITICAL | Unset |
| EC2-001 | IPv4 internet ingress overlaps configured sensitive ports | HIGH | Unset |
| EC2-002 | IPv6 internet ingress overlaps configured sensitive ports | HIGH | Unset |

The S3 policy rule uses the collected policy status as the public classification
and accounts for `RestrictPublicBuckets`; `BlockPublicPolicy` alone does not
neutralize an existing public policy. The ACL rule recognizes the S3
`AllUsers` and `AuthenticatedUsers` groups and accounts for
`IgnorePublicAcls`; `BlockPublicAcls` alone only prevents new public ACLs. The
S3-003 finding reports incomplete bucket-level controls and explicitly does not
claim that the bucket is currently public. Missing or malformed evidence is an
evaluation error. Phase 4 collects bucket-level, not account-level, Block Public
Access settings. S3 findings therefore describe public grants and bucket-level
controls present in the collected data; they do not verify effective access
against account-level controls.

`AssessmentResult.is_complete` is false whenever any evaluation error exists.
One evaluation can retain a confirmed finding and report separate malformed or
unsupported evidence at the same time. An empty `findings` collection alone does
not establish a clean assessment; check `is_complete` and `errors` as well.

IAM-001 detects `Allow` statements with `Action: "*"`, service-wide action
wildcards such as `s3:*`, `NotAction`, or `NotResource`.
Wildcard resources are included as evidence when combined with wildcard
actions; a wildcard resource by itself with a scoped action is not labeled
overprivileged. `Deny` statements do not trigger findings. Conditional broad
statements are reported as unevaluable because this project is not an IAM
authorization simulator. The rule evaluates inline and managed policy
documents collected in Phase 4. IAM-002 detects an unconditional wildcard
principal allowed to call an STS assume-role action; conditional wildcard trust
statements are unevaluable rather than assumed safe or unsafe.

EC2 rules inspect ingress only. They match `0.0.0.0/0` and `::/0` separately,
support TCP, UDP, and all-protocol rules, and test port-range overlap. Egress is
not evaluated. The configurable TCP baseline is ports `22,23,445,1433,3306,3389,5432,6379,27017`.
Override it with the comma-separated `CSPM_SENSITIVE_PORTS` environment value.
UDP ports default to none and can be configured separately with
`CSPM_SENSITIVE_UDP_PORTS`. Both settings accept ports 1–65535; duplicates are
removed and values are sorted. This baseline is a configurable starting point,
not an exhaustive dangerous-port list or a CIS requirement. An empty effective
port configuration produces an evaluation error rather than a clean result.

Each finding uses the existing finding model, UTC detection time, and
`generate_fingerprint(rule_id, resource_type, resource_id)`. Fingerprints stay
stable across scans while finding IDs and detection times are newly generated.
CIS control and version mappings remain unset until a benchmark edition is
selected and each mapping is verified against that edition.

To add a rule, subclass `BaseRule`, provide a validated `Rule` as its
`definition`, implement `evaluate(resource)`, then register an instance with
`AssessmentEngine.register()`. The engine does not need to be modified.

## Tests and lint

```powershell
uv run pytest
uv run ruff check .
```

## Development status

The core models, LocalStack connectivity, Phase 4 read-only resource discovery,
and Phase 5 rule assessment are implemented. Persistence, generated reports,
and scan comparison remain future work. The application does not connect to
real AWS accounts.
