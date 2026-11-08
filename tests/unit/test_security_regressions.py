"""Regression tests for the issues found in the November 2026 security review."""

import json
import os
import stat
import sys
from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from click.testing import CliRunner

from cspm.aws.client_factory import create_client
from cspm.cli import main
from cspm.config import load_config
from cspm.models import (
    CollectorError,
    CollectorResult,
    CollectorStatus,
    Resource,
    Scan,
    ScanStatus,
    TargetType,
)
from cspm.persistence import ScanRepository
from cspm.reporting.writer import generate_reports
from cspm.rules import AssessmentResult
from cspm.rules.base import EvaluationStatus
from cspm.rules.ec2 import EC2SensitiveIpv4IngressRule
from cspm.rules.iam import IamWildcardTrustRule
from cspm.scan_service import ScanExecutionResult

SCAN_ID = uuid4()


def _role(statements):
    return Resource(
        scan_id=SCAN_ID,
        resource_id="arn:aws:iam::111122223333:role/r",
        resource_type="iam_role",
        region="global",
        raw_metadata={
            "assume_role_trust_policy": {
                "Version": "2012-10-17",
                "Statement": statements,
            }
        },
    )


def _sg(*cidrs, port=22):
    return Resource(
        scan_id=SCAN_ID,
        resource_id="sg-1",
        resource_type="security_group",
        region="us-east-1",
        raw_metadata={
            "ingress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": cidr} for cidr in cidrs],
                }
            ]
        },
    )


# H2 -------------------------------------------------------------------------
@pytest.mark.parametrize(
    "action",
    [
        "sts:AssumeRole",
        "sts:*",
        "sts:Assume*",
        "sts:AssumeRole*",
        "*",
        "STS:ASSUME*",
        ["sts:TagSession", "sts:*"],
        "sts:AssumeRol?",
    ],
)
def test_iam_002_flags_wildcard_principal_for_any_assume_role_pattern(action):
    result = IamWildcardTrustRule().evaluate(
        _role([{"Effect": "Allow", "Principal": "*", "Action": action}])
    )
    assert result.status is EvaluationStatus.FINDING


@pytest.mark.parametrize("action", ["sts:TagSession", "sts:GetCallerIdentity", "s3:*"])
def test_iam_002_ignores_unrelated_actions(action):
    result = IamWildcardTrustRule().evaluate(
        _role([{"Effect": "Allow", "Principal": "*", "Action": action}])
    )
    assert result.status is EvaluationStatus.PASSED


# M3 -------------------------------------------------------------------------
def test_ec2_001_detects_internet_split_into_halves():
    rule = EC2SensitiveIpv4IngressRule(load_config({}).sensitive_ports)
    result = rule.evaluate(_sg("0.0.0.0/1", "128.0.0.0/1"))
    assert result.status is EvaluationStatus.FINDING
    exposure = result.evidence["exposures"][0]
    assert exposure["cidr"] == "0.0.0.0/0"
    assert exposure["source_cidrs"] == ["0.0.0.0/1", "128.0.0.0/1"]


def test_ec2_001_partial_internet_is_not_reported_as_full_exposure():
    rule = EC2SensitiveIpv4IngressRule(load_config({}).sensitive_ports)
    assert rule.evaluate(_sg("0.0.0.0/1")).status is EvaluationStatus.PASSED


# M2 -------------------------------------------------------------------------
def test_client_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    client = create_client("sts", load_config({}))
    assert client.meta.config.proxies == {}


# L1 -------------------------------------------------------------------------
def test_s3_acl_does_not_persist_response_metadata():
    from cspm.collectors.s3 import S3Collector

    class FakeClient:
        meta = None

        def get_bucket_acl(self, Bucket):
            return {
                "Owner": {"ID": "abc"},
                "Grants": [],
                "ResponseMetadata": {"RequestId": "R", "HTTPHeaders": {"x": "y"}},
            }

    acl = S3Collector(load_config({}), FakeClient())._acl("b")
    assert set(acl) == {"Owner", "Grants"}


# M1 -------------------------------------------------------------------------
def test_cli_scan_output_does_not_interpret_markup_from_resource_ids():
    from cspm.rules.engine import EvaluationRecord

    scan = Scan(
        scan_id=uuid4(),
        target=TargetType.LOCALSTACK,
        region="us-east-1",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        status=ScanStatus.COMPLETED,
        collector_results=[
            CollectorResult(
                collector_name="iam",
                status=CollectorStatus.SUCCESS,
                resources_discovered=0,
            )
        ],
    )
    hostile = "arn:aws:iam::111122223333:role/[/]/[green]ALL-CLEAR[/green]"
    record = EvaluationRecord(
        resource_id=hostile,
        resource_type="iam_role",
        rule_id="IAM-002",
        status=EvaluationStatus.ERROR,
        error_code="X",
        message="incomplete",
    )
    with patch(
        "cspm.cli.run_scan", return_value=ScanExecutionResult(scan, (), (), (record,))
    ):
        result = CliRunner().invoke(main, ["scan", "--database", "x.sqlite3"])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "[green]ALL-CLEAR[/green]" in result.output  # shown literally


# H1 -------------------------------------------------------------------------
def _persist_scan(repo, collector_results):
    now = datetime.now(UTC)
    sid = uuid4()
    repo.initialize()
    repo.create_scan(
        Scan(
            scan_id=sid,
            target=TargetType.LOCALSTACK,
            region="us-east-1",
            started_at=now,
            status=ScanStatus.RUNNING,
        )
    )
    repo.persist_assessment(sid, AssessmentResult(()))
    repo.update_scan(
        Scan(
            scan_id=sid,
            target=TargetType.LOCALSTACK,
            region="us-east-1",
            started_at=now,
            completed_at=datetime.now(UTC),
            status=ScanStatus.COMPLETED,
            collector_results=collector_results,
        )
    )
    return sid


def _failed(name):
    return CollectorResult(
        collector_name=name,
        status=CollectorStatus.FAILED,
        resources_discovered=0,
        errors=[
            CollectorError(
                error_code="AccessDenied",
                message="x failed (AccessDenied).",
                operation="ListX",
            )
        ],
    )


@pytest.mark.parametrize(
    "collectors",
    [
        [_failed("s3"), _failed("iam")],
        [],  # coverage never recorded must not read as clean either
    ],
)
def test_reports_never_claim_clean_when_discovery_incomplete(tmp_path, collectors):
    repo = ScanRepository(tmp_path / "db" / "s.sqlite3")
    sid = _persist_scan(repo, collectors)
    paths = generate_reports(repo, sid, formats="all", output_dir=tmp_path / "out")
    for fmt in ("markdown", "html"):
        text = paths[fmt].read_text()
        assert "Assessment ran without recorded evaluation errors" not in text
        assert "ncomplete discovery" in text
    doc = json.loads(paths["json"].read_text())
    assert doc["collectors"]["complete"] is False


def test_reports_still_claim_clean_when_all_collectors_succeed(tmp_path):
    ok = [
        CollectorResult(
            collector_name="s3", status=CollectorStatus.SUCCESS, resources_discovered=0
        )
    ]
    repo = ScanRepository(tmp_path / "db" / "s.sqlite3")
    sid = _persist_scan(repo, ok)
    paths = generate_reports(repo, sid, formats="markdown", output_dir=tmp_path / "out")
    assert (
        "Assessment ran without recorded evaluation errors"
        in paths["markdown"].read_text()
    )


# M5 -------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_database_and_report_directories_are_owner_only(tmp_path):
    old = os.umask(0o022)
    try:
        repo = ScanRepository(tmp_path / "data" / "s.sqlite3")
        sid = _persist_scan(repo, [])
        paths = generate_reports(
            repo, sid, formats="json", output_dir=tmp_path / "reports"
        )
    finally:
        os.umask(old)
    mode = lambda p: stat.S_IMODE(p.stat().st_mode)  # noqa: E731
    assert mode(tmp_path / "data" / "s.sqlite3") == 0o600
    assert mode(tmp_path / "data") == 0o700
    assert mode(paths["json"].parent) == 0o700
