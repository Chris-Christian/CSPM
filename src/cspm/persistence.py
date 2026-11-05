"""SQLite persistence for CSPM scans, resources, findings, and rules."""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from os import PathLike
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from cspm.models import (
    Finding,
    Resource,
    Rule,
    Scan,
)
from cspm.rules import AssessmentResult, EvaluationRecord, EvaluationStatus


class RepositoryError(RuntimeError):
    """Base exception for SQLite repository failures."""


class RepositoryIntegrityError(RepositoryError):
    """A record violates an identifier, uniqueness, or foreign-key constraint."""


class RepositoryNotFoundError(RepositoryError):
    """A requested database record does not exist."""


class RepositorySerializationError(RepositoryError):
    """An in-memory value cannot be represented by the repository schema."""


class RepositoryDataError(RepositoryError):
    """A stored value is malformed or cannot reconstruct its approved model."""


class RepositorySchemaError(RepositoryError):
    """An existing SQLite database does not match the repository schema."""


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY NOT NULL,
        target TEXT NOT NULL CHECK (target IN ('aws', 'localstack')),
        region TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
        collector_results_json TEXT NOT NULL,
        assessment_errors_json TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS resources (
        scan_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        region TEXT NOT NULL,
        raw_metadata_json TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, resource_id),
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS rules (
        rule_id TEXT PRIMARY KEY NOT NULL,
        title TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (
            severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        ),
        cis_control TEXT,
        cis_version TEXT,
        remediation_text TEXT NOT NULL,
        CHECK ((cis_control IS NULL) = (cis_version IS NULL))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY NOT NULL,
        fingerprint TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (
            severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        ),
        cis_control TEXT,
        remediation TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        detected_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id),
        FOREIGN KEY (rule_id) REFERENCES rules (rule_id),
        FOREIGN KEY (scan_id, resource_id)
            REFERENCES resources (scan_id, resource_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)",
    """CREATE INDEX IF NOT EXISTS idx_findings_rule_resource
       ON findings (rule_id, resource_id)""",
)

_ASSESSMENT_ERROR_KEYS = {
    "resource_id",
    "resource_type",
    "rule_id",
    "status",
    "error_code",
    "message",
    "detail_code",
    "error_codes",
    "finding_id",
}


def _read_only_database_uri(path: Path) -> str:
    """Build a SQLite read-only URI with path metacharacters safely escaped."""
    return f"{path.absolute().as_uri()}?mode=ro"


def _reject_read_only_sidecar_access(path: Path) -> None:
    """Reject SQLite formats or sidecar states unsafe for read-only reporting."""
    try:
        with path.open("rb") as database_file:
            header = database_file.read(100)
    except FileNotFoundError:
        return
    except OSError:
        raise RepositoryError(
            "SQLite database state could not be inspected; check file access"
        ) from None

    if (
        len(header) < 100
        or header[:16] != b"SQLite format 3\x00"
        or header[18:20] not in {b"\x01\x01", b"\x02\x02"}
    ):
        raise RepositoryError(
            "unsupported SQLite database format or journal state for reporting"
        )

    for suffix in ("-wal", "-shm"):
        try:
            Path(f"{path}{suffix}").stat()
        except FileNotFoundError:
            continue
        except OSError:
            raise RepositoryError(
                "SQLite WAL/SHM sidecar state could not be inspected; check file access"
            ) from None
        raise RepositoryError(
            "an SQLite WAL or shared-memory sidecar exists; create a consistent "
            "standalone database with SQLite's backup facility"
        )

    if header[18:20] == b"\x02\x02":
        raise RepositoryError(
            "WAL journal mode is unsupported for reporting; create a consistent "
            "standalone database with SQLite's backup facility"
        )

    try:
        Path(f"{path}-journal").stat()
    except FileNotFoundError:
        return
    except OSError:
        raise RepositoryError(
            "SQLite rollback-journal state could not be inspected; check file access"
        ) from None
    raise RepositoryError(
        "an SQLite rollback journal exists; wait for database recovery or active "
        "transactions to finish before reporting"
    )


class ScanRepository:
    """Own all SQLite access for CSPM scan and assessment data.

    The caller supplies a database path explicitly. This avoids creating a
    hidden project database when the current application has no persistence
    configuration or established default location.
    """

    def __init__(self, db_path: str | PathLike[str]) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def _connection(self, *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            if read_only:
                _reject_read_only_sidecar_access(self.db_path)
                database_uri = _read_only_database_uri(self.db_path)
                connection = sqlite3.connect(database_uri, uri=True)
            else:
                connection = sqlite3.connect(self.db_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]
            if enabled != 1:
                raise RepositoryError("SQLite foreign-key enforcement is unavailable")
        except sqlite3.Error:
            if connection is not None:
                connection.close()
            raise RepositoryError("SQLite database connection failed") from None
        except BaseException:
            if connection is not None:
                connection.close()
            raise
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            try:
                yield connection
                connection.commit()
            except sqlite3.IntegrityError:
                connection.rollback()
                raise RepositoryIntegrityError(
                    "database integrity constraint failed"
                ) from None
            except sqlite3.Error:
                connection.rollback()
                raise RepositoryError("SQLite database operation failed") from None
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _read_error() -> RepositoryError:
        return RepositoryError("SQLite database read failed")

    def initialize(self) -> None:
        """Create the approved four-table schema and indexes idempotently."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise RepositoryError("database directory could not be created") from None
        with self._transaction() as connection:
            connection.execute("BEGIN")
            for statement in _SCHEMA:
                connection.execute(statement)
            self._validate_schema(connection)

    def validate_schema(self) -> None:
        """Validate an existing database without creating or changing schema."""
        try:
            with self._connection(read_only=True) as connection:
                self._validate_schema(connection)
        except RepositorySchemaError:
            raise
        except sqlite3.Error:
            raise RepositoryError("SQLite database schema validation failed") from None

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        """Reject an existing database that differs from the approved schema."""
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RepositorySchemaError(
                "schema validation requires SQLite foreign-key enforcement"
            )

        expected_tables = {"scans", "resources", "findings", "rules"}
        actual_tables = {
            row[0]
            for row in connection.execute(
                """SELECT name FROM sqlite_master
                   WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"""
            )
        }
        if actual_tables != expected_tables:
            missing = sorted(expected_tables - actual_tables)
            unexpected = sorted(actual_tables - expected_tables)
            details = []
            if missing:
                details.append(f"missing tables: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected tables: {', '.join(unexpected)}")
            raise RepositorySchemaError(
                "schema tables mismatch (" + "; ".join(details) + ")"
            )

        expected_columns: dict[str, dict[str, tuple[str, int, int]]] = {
            "scans": {
                "scan_id": ("TEXT", 1, 1),
                "target": ("TEXT", 1, 0),
                "region": ("TEXT", 1, 0),
                "started_at": ("TEXT", 1, 0),
                "completed_at": ("TEXT", 0, 0),
                "status": ("TEXT", 1, 0),
                "collector_results_json": ("TEXT", 1, 0),
                "assessment_errors_json": ("TEXT", 0, 0),
            },
            "resources": {
                "scan_id": ("TEXT", 1, 1),
                "resource_id": ("TEXT", 1, 2),
                "resource_type": ("TEXT", 1, 0),
                "region": ("TEXT", 1, 0),
                "raw_metadata_json": ("TEXT", 1, 0),
                "tags_json": ("TEXT", 1, 0),
            },
            "rules": {
                "rule_id": ("TEXT", 1, 1),
                "title": ("TEXT", 1, 0),
                "resource_type": ("TEXT", 1, 0),
                "severity": ("TEXT", 1, 0),
                "cis_control": ("TEXT", 0, 0),
                "cis_version": ("TEXT", 0, 0),
                "remediation_text": ("TEXT", 1, 0),
            },
            "findings": {
                "finding_id": ("TEXT", 1, 1),
                "fingerprint": ("TEXT", 1, 0),
                "scan_id": ("TEXT", 1, 0),
                "rule_id": ("TEXT", 1, 0),
                "resource_id": ("TEXT", 1, 0),
                "title": ("TEXT", 1, 0),
                "severity": ("TEXT", 1, 0),
                "cis_control": ("TEXT", 0, 0),
                "remediation": ("TEXT", 1, 0),
                "evidence_json": ("TEXT", 1, 0),
                "detected_at": ("TEXT", 1, 0),
            },
        }
        for table, expected in expected_columns.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = {
                row["name"]: (row["type"].upper(), row["notnull"], row["pk"])
                for row in rows
            }
            if actual != expected:
                missing = sorted(expected.keys() - actual.keys())
                unexpected = sorted(actual.keys() - expected.keys())
                mismatched = sorted(
                    name
                    for name in expected.keys() & actual.keys()
                    if expected[name][:2] != actual[name][:2]
                )
                expected_pk = tuple(
                    name
                    for _, name in sorted(
                        (definition[2], name)
                        for name, definition in expected.items()
                        if definition[2]
                    )
                )
                actual_pk = tuple(
                    row["name"]
                    for row in sorted(rows, key=lambda row: row["pk"])
                    if row["pk"]
                )
                details = []
                if missing:
                    details.append(f"missing columns: {', '.join(missing)}")
                if unexpected:
                    details.append(f"unexpected columns: {', '.join(unexpected)}")
                if mismatched:
                    details.append(f"incompatible columns: {', '.join(mismatched)}")
                if actual_pk != expected_pk:
                    details.append(
                        "primary key mismatch: "
                        f"expected {expected_pk}, found {actual_pk}"
                    )
                raise RepositorySchemaError(
                    f"table {table} schema mismatch (" + "; ".join(details) + ")"
                )

        expected_checks = {
            "scans": (
                "check(targetin('aws','localstack'))",
                "check(statusin('running','completed','failed'))",
            ),
            "rules": (
                "check(severityin('critical','high','medium','low'))",
                "check((cis_controlisnull)=(cis_versionisnull))",
            ),
            "findings": ("check(severityin('critical','high','medium','low'))",),
        }
        for table, checks in expected_checks.items():
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            normalized_sql = "".join(row["sql"].casefold().split())
            for check in checks:
                if check not in normalized_sql:
                    raise RepositorySchemaError(
                        f"table {table} is missing required constraint {check}"
                    )

        expected_foreign_keys = {
            "resources": {
                ("scans", (("scan_id", "scan_id"),), "NO ACTION", "NO ACTION")
            },
            "findings": {
                ("scans", (("scan_id", "scan_id"),), "NO ACTION", "NO ACTION"),
                ("rules", (("rule_id", "rule_id"),), "NO ACTION", "NO ACTION"),
                (
                    "resources",
                    (("scan_id", "scan_id"), ("resource_id", "resource_id")),
                    "NO ACTION",
                    "NO ACTION",
                ),
            },
            "scans": set(),
            "rules": set(),
        }
        for table, expected in expected_foreign_keys.items():
            grouped: dict[int, list[sqlite3.Row]] = {}
            for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
                grouped.setdefault(row["id"], []).append(row)
            actual = set()
            for rows in grouped.values():
                ordered = sorted(rows, key=lambda row: row["seq"])
                actual.add(
                    (
                        ordered[0]["table"],
                        tuple((row["from"], row["to"]) for row in ordered),
                        ordered[0]["on_update"],
                        ordered[0]["on_delete"],
                    )
                )
            if actual != expected:
                raise RepositorySchemaError(
                    f"table {table} foreign keys do not match the approved schema"
                )

        expected_indexes = {
            "idx_findings_scan_id": ("scan_id",),
            "idx_findings_rule_resource": ("rule_id", "resource_id"),
        }
        index_rows = {
            row["name"]: row
            for row in connection.execute("PRAGMA index_list(findings)")
        }
        for name, columns in expected_indexes.items():
            index = index_rows.get(name)
            if index is None:
                raise RepositorySchemaError(f"missing index findings.{name}")
            if index["unique"] != 0 or index["partial"] != 0:
                raise RepositorySchemaError(
                    f"index findings.{name} has incompatible uniqueness or predicate"
                )
            actual_columns = tuple(
                row["name"] for row in connection.execute(f"PRAGMA index_info({name})")
            )
            if actual_columns != columns:
                raise RepositorySchemaError(
                    f"index findings.{name} columns mismatch: expected {columns}, "
                    f"found {actual_columns}"
                )

    def create_scan(self, scan: Scan) -> None:
        """Insert a scan without replacing an existing scan with the same ID."""
        values = _scan_values(scan)
        try:
            with self._transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO scans (
                        scan_id, target, region, started_at, completed_at,
                        status, collector_results_json, assessment_errors_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    values,
                )
        except RepositoryIntegrityError:
            raise RepositoryIntegrityError(
                "scan already exists or is invalid"
            ) from None

    def update_scan(self, scan: Scan) -> None:
        """Update lifecycle fields and collector results for an existing scan.

        Identity, target, region, and start time are immutable after insertion.
        Assessment errors are updated only by :meth:`persist_assessment`.
        """
        collector_json = _json_text(
            [result.model_dump(mode="json") for result in scan.collector_results],
            "collector results",
        )
        completed_at = _timestamp_text(scan.completed_at, optional=True)
        try:
            with self._transaction() as connection:
                cursor = connection.execute(
                    """
                    UPDATE scans
                    SET completed_at = ?, status = ?, collector_results_json = ?
                    WHERE scan_id = ?
                    """,
                    (
                        completed_at,
                        scan.status.value,
                        collector_json,
                        str(scan.scan_id),
                    ),
                )
                if cursor.rowcount == 0:
                    raise RepositoryNotFoundError("scan does not exist")
        except RepositoryNotFoundError:
            raise

    def get_scan(self, scan_id: UUID) -> Scan | None:
        """Return a validated scan, or ``None`` when its ID is not present."""
        try:
            with self._connection(read_only=True) as connection:
                row = connection.execute(
                    "SELECT * FROM scans WHERE scan_id = ?", (str(scan_id),)
                ).fetchone()
        except sqlite3.Error:
            raise self._read_error() from None
        if row is None:
            return None
        try:
            collectors = _json_value(row["collector_results_json"], "scan collectors")
            if not isinstance(collectors, list):
                raise RepositoryDataError("stored collector results are not a list")
            return Scan.model_validate(
                {
                    "scan_id": row["scan_id"],
                    "target": row["target"],
                    "region": row["region"],
                    "started_at": _parse_timestamp(row["started_at"], "scan start"),
                    "completed_at": (
                        _parse_timestamp(row["completed_at"], "scan completion")
                        if row["completed_at"] is not None
                        else None
                    ),
                    "status": row["status"],
                    "collector_results": collectors,
                }
            )
        except (ValidationError, ValueError, TypeError):
            raise RepositoryDataError("stored scan record is invalid") from None

    def save_resources(self, resources: Iterable[Resource]) -> None:
        """Insert resources atomically; duplicate composite identities fail."""
        rows = [_resource_values(resource) for resource in resources]
        try:
            with self._transaction() as connection:
                connection.executemany(
                    """
                    INSERT INTO resources (
                        scan_id, resource_id, resource_type, region,
                        raw_metadata_json, tags_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
        except RepositoryIntegrityError:
            raise RepositoryIntegrityError(
                "resource identity already exists or its scan is missing"
            ) from None

    def get_resources(self, scan_id: UUID) -> list[Resource]:
        """Return all resources for a scan in stable identity order."""
        try:
            with self._connection(read_only=True) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM resources WHERE scan_id = ?
                    ORDER BY resource_type, resource_id
                    """,
                    (str(scan_id),),
                ).fetchall()
        except sqlite3.Error:
            raise self._read_error() from None
        return [_resource_from_row(row) for row in rows]

    def save_findings(self, findings: Iterable[Finding]) -> None:
        """Insert findings atomically without overwriting historical records."""
        rows = [_finding_values(finding) for finding in findings]
        try:
            with self._transaction() as connection:
                connection.executemany(
                    """
                    INSERT INTO findings (
                        finding_id, fingerprint, scan_id, rule_id, resource_id,
                        title, severity, cis_control, remediation, evidence_json,
                        detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
        except RepositoryIntegrityError:
            raise RepositoryIntegrityError(
                "finding already exists or references a missing scan, rule, or resource"
            ) from None

    def get_findings(self, scan_id: UUID) -> list[Finding]:
        """Return validated findings for a scan in stable order."""
        try:
            with self._connection(read_only=True) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM findings WHERE scan_id = ?
                    ORDER BY rule_id, resource_id, finding_id
                    """,
                    (str(scan_id),),
                ).fetchall()
        except sqlite3.Error:
            raise self._read_error() from None
        return [_finding_from_row(row) for row in rows]

    def sync_rules(self, rules: Iterable[Rule]) -> None:
        """Upsert the current rule definitions without deleting old definitions."""
        rows = [_rule_values(rule) for rule in rules]
        try:
            with self._transaction() as connection:
                connection.executemany(
                    """
                    INSERT INTO rules (
                        rule_id, title, resource_type, severity, cis_control,
                        cis_version, remediation_text
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        title = excluded.title,
                        resource_type = excluded.resource_type,
                        severity = excluded.severity,
                        cis_control = excluded.cis_control,
                        cis_version = excluded.cis_version,
                        remediation_text = excluded.remediation_text
                    """,
                    rows,
                )
        except RepositoryIntegrityError:
            raise RepositoryIntegrityError("rule definitions are invalid") from None

    def get_rule(self, rule_id: str) -> Rule | None:
        """Return one validated rule definition, if it exists."""
        try:
            with self._connection(read_only=True) as connection:
                row = connection.execute(
                    "SELECT * FROM rules WHERE rule_id = ?", (rule_id,)
                ).fetchone()
        except sqlite3.Error:
            raise self._read_error() from None
        return _rule_from_row(row) if row is not None else None

    def get_rules(self) -> list[Rule]:
        """Return all stored definitions ordered by rule ID."""
        try:
            with self._connection(read_only=True) as connection:
                rows = connection.execute(
                    "SELECT * FROM rules ORDER BY rule_id"
                ).fetchall()
        except sqlite3.Error:
            raise self._read_error() from None
        return [_rule_from_row(row) for row in rows]

    def persist_assessment(self, scan_id: UUID, result: AssessmentResult) -> None:
        """Persist findings and assessment errors atomically for one scan.

        An assessment with no errors is stored as ``[]``. SQL NULL remains the
        marker for a scan whose rules have not yet been evaluated.
        """
        if not isinstance(result, AssessmentResult):
            raise TypeError("result must be an AssessmentResult")
        findings = result.findings
        if any(finding.scan_id != scan_id for finding in findings):
            raise RepositorySerializationError(
                "assessment contains a finding for a different scan"
            )
        errors_json = _json_text(
            [_assessment_error_value(item) for item in result.errors],
            "assessment errors",
        )
        finding_rows = [_finding_values(finding) for finding in findings]
        try:
            with self._transaction() as connection:
                connection.executemany(
                    """
                    INSERT INTO findings (
                        finding_id, fingerprint, scan_id, rule_id, resource_id,
                        title, severity, cis_control, remediation, evidence_json,
                        detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    finding_rows,
                )
                cursor = connection.execute(
                    """
                    UPDATE scans SET assessment_errors_json = ? WHERE scan_id = ?
                    """,
                    (errors_json, str(scan_id)),
                )
                if cursor.rowcount == 0:
                    raise RepositoryNotFoundError("scan does not exist")
        except RepositoryNotFoundError:
            raise
        except RepositoryIntegrityError:
            raise RepositoryIntegrityError(
                "assessment findings already exist or reference missing records"
            ) from None

    def get_assessment_errors(
        self, scan_id: UUID
    ) -> tuple[EvaluationRecord, ...] | None:
        """Return stored evaluation errors; ``None`` means not assessed yet."""
        try:
            with self._connection(read_only=True) as connection:
                row = connection.execute(
                    """
                    SELECT assessment_errors_json FROM scans WHERE scan_id = ?
                    """,
                    (str(scan_id),),
                ).fetchone()
                if row is None:
                    raise RepositoryNotFoundError("scan does not exist")
                stored = row["assessment_errors_json"]
                if stored is None:
                    return None
                values = _json_value(stored, "assessment errors")
                if not isinstance(values, list):
                    raise RepositoryDataError("stored assessment errors are not a list")
                findings_by_id: dict[str, Finding] = {}
                finding_ids = [
                    value.get("finding_id")
                    for value in values
                    if isinstance(value, dict) and value.get("finding_id") is not None
                ]
                if finding_ids:
                    for finding_id in dict.fromkeys(finding_ids):
                        if not isinstance(finding_id, str):
                            raise RepositoryDataError(
                                "stored assessment finding identity is invalid"
                            )
                        finding_row = connection.execute(
                            """SELECT * FROM findings
                               WHERE scan_id = ? AND finding_id = ?""",
                            (str(scan_id), finding_id),
                        ).fetchone()
                        if finding_row is not None:
                            finding = _finding_from_row(finding_row)
                            findings_by_id[str(finding.finding_id)] = finding
        except RepositoryNotFoundError:
            raise
        except RepositoryDataError:
            raise
        except sqlite3.Error:
            raise self._read_error() from None

        errors: list[EvaluationRecord] = []
        for value in values:
            if not isinstance(value, dict) or set(value) != _ASSESSMENT_ERROR_KEYS:
                raise RepositoryDataError("stored assessment error record is invalid")
            try:
                if value["status"] != EvaluationStatus.ERROR.value:
                    raise ValueError
                if not isinstance(value["resource_id"], str) or not isinstance(
                    value["resource_type"], str
                ):
                    raise ValueError
                rule_id = value["rule_id"]
                error_code = value["error_code"]
                message = value["message"]
                detail_code = value["detail_code"]
                error_codes = value["error_codes"]
                if rule_id is not None and not isinstance(rule_id, str):
                    raise ValueError
                if not isinstance(error_code, str) or not isinstance(message, str):
                    raise ValueError
                if (
                    not error_code.strip()
                    or not message.strip()
                    or detail_code is not None
                ):
                    raise ValueError
                if (
                    not isinstance(error_codes, list)
                    or not error_codes
                    or any(not isinstance(code, str) for code in error_codes)
                ):
                    raise ValueError
                if any(not code.strip() for code in error_codes):
                    raise ValueError
                if error_codes and error_codes[0] != error_code:
                    raise ValueError
                finding_id = value["finding_id"]
                finding = None
                if finding_id is not None:
                    if not isinstance(finding_id, str):
                        raise ValueError
                    finding = findings_by_id.get(finding_id)
                    if finding is None:
                        raise RepositoryDataError(
                            "stored assessment error references a missing finding"
                        )
                    if (
                        finding.resource_id != value["resource_id"]
                        or finding.rule_id != rule_id
                    ):
                        raise RepositoryDataError(
                            "stored assessment error finding identity is inconsistent"
                        )
                errors.append(
                    EvaluationRecord(
                        resource_id=value["resource_id"],
                        resource_type=value["resource_type"],
                        rule_id=rule_id,
                        status=EvaluationStatus.ERROR,
                        finding=finding,
                        error_code=error_code,
                        message=message,
                        detail_code=detail_code,
                        error_codes=tuple(error_codes),
                    )
                )
            except (TypeError, ValueError):
                raise RepositoryDataError(
                    "stored assessment error record is invalid"
                ) from None
        return tuple(errors)


def _json_text(value: object, field: str) -> str:
    """Serialize strict JSON data deterministically without coercing values."""
    active: set[int] = set()

    def validate(item: object) -> None:
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise RepositorySerializationError(
                    f"{field} contains a non-finite float"
                )
            return
        if type(item) not in (dict, list):
            raise RepositorySerializationError(f"{field} contains a non-JSON value")
        identity = id(item)
        if identity in active:
            raise RepositorySerializationError(f"{field} contains a cyclic value")
        active.add(identity)
        try:
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise RepositorySerializationError(
                            f"{field} contains a non-string object key"
                        )
                    validate(child)
            else:
                for child in item:
                    validate(child)
        finally:
            active.remove(identity)

    validate(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError):
        raise RepositorySerializationError(
            f"{field} cannot be serialized as JSON"
        ) from None


def _json_value(text: str, field: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise ValueError("non-standard JSON constant")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise RepositoryDataError(f"stored {field} JSON is malformed") from None


def _timestamp_text(value: datetime | None, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if value is None or value.utcoffset() is None:
        raise RepositorySerializationError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise RepositoryDataError(f"stored {field} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise RepositoryDataError(f"stored {field} timestamp is invalid") from None
    if parsed.utcoffset() is None:
        raise RepositoryDataError(f"stored {field} timestamp is naive")
    return parsed.astimezone(UTC)


def _scan_values(scan: Scan) -> tuple[str, ...]:
    if not isinstance(scan, Scan):
        raise TypeError("scan must be a Scan model")
    try:
        scan = Scan.model_validate(scan.model_dump(mode="python"))
    except ValidationError:
        raise RepositorySerializationError("scan failed model validation") from None
    collectors = _json_text(
        [result.model_dump(mode="json") for result in scan.collector_results],
        "collector results",
    )
    return (
        str(scan.scan_id),
        scan.target.value,
        scan.region,
        _timestamp_text(scan.started_at),
        _timestamp_text(scan.completed_at, optional=True),
        scan.status.value,
        collectors,
    )


def _resource_values(resource: Resource) -> tuple[str, ...]:
    if not isinstance(resource, Resource):
        raise TypeError("resources must contain Resource models")
    try:
        resource = Resource.model_validate(resource.model_dump(mode="python"))
    except ValidationError:
        raise RepositorySerializationError("resource failed model validation") from None
    return (
        str(resource.scan_id),
        resource.resource_id,
        resource.resource_type,
        resource.region,
        _json_text(resource.raw_metadata, "resource metadata"),
        _json_text(resource.tags, "resource tags"),
    )


def _finding_values(finding: Finding) -> tuple[str | None, ...]:
    if not isinstance(finding, Finding):
        raise TypeError("findings must contain Finding models")
    try:
        finding = Finding.model_validate(finding.model_dump(mode="python"))
    except ValidationError:
        raise RepositorySerializationError("finding failed model validation") from None
    return (
        str(finding.finding_id),
        finding.fingerprint,
        str(finding.scan_id),
        finding.rule_id,
        finding.resource_id,
        finding.title,
        finding.severity.value,
        finding.cis_control,
        finding.remediation,
        _json_text(finding.evidence, "finding evidence"),
        _timestamp_text(finding.detected_at),
    )


def _rule_values(rule: Rule) -> tuple[str | None, ...]:
    if not isinstance(rule, Rule):
        raise TypeError("rules must contain Rule models")
    try:
        rule = Rule.model_validate(rule.model_dump(mode="python"))
    except ValidationError:
        raise RepositorySerializationError("rule failed model validation") from None
    return (
        rule.rule_id,
        rule.title,
        rule.resource_type,
        rule.severity.value,
        rule.cis_control,
        rule.cis_version,
        rule.remediation_text,
    )


def _resource_from_row(row: sqlite3.Row) -> Resource:
    try:
        metadata = _json_value(row["raw_metadata_json"], "resource metadata")
        tags = _json_value(row["tags_json"], "resource tags")
        if not isinstance(metadata, dict) or not isinstance(tags, dict):
            raise RepositoryDataError("stored resource JSON has an invalid shape")
        return Resource.model_validate(
            {
                "scan_id": row["scan_id"],
                "resource_id": row["resource_id"],
                "resource_type": row["resource_type"],
                "region": row["region"],
                "raw_metadata": metadata,
                "tags": tags,
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise RepositoryDataError("stored resource record is invalid") from None


def _finding_from_row(row: sqlite3.Row) -> Finding:
    try:
        evidence = _json_value(row["evidence_json"], "finding evidence")
        if not isinstance(evidence, dict):
            raise RepositoryDataError("stored finding evidence is not an object")
        return Finding.model_validate(
            {
                "finding_id": row["finding_id"],
                "fingerprint": row["fingerprint"],
                "scan_id": row["scan_id"],
                "rule_id": row["rule_id"],
                "resource_id": row["resource_id"],
                "title": row["title"],
                "severity": row["severity"],
                "cis_control": row["cis_control"],
                "remediation": row["remediation"],
                "evidence": evidence,
                "detected_at": _parse_timestamp(row["detected_at"], "finding"),
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise RepositoryDataError("stored finding record is invalid") from None


def _rule_from_row(row: sqlite3.Row) -> Rule:
    try:
        return Rule.model_validate(
            {
                "rule_id": row["rule_id"],
                "title": row["title"],
                "resource_type": row["resource_type"],
                "severity": row["severity"],
                "cis_control": row["cis_control"],
                "cis_version": row["cis_version"],
                "remediation_text": row["remediation_text"],
            }
        )
    except (ValidationError, TypeError, ValueError):
        raise RepositoryDataError("stored rule record is invalid") from None


def _assessment_error_value(record: EvaluationRecord) -> dict[str, Any]:
    if not isinstance(record, EvaluationRecord):
        raise RepositorySerializationError(
            "assessment errors contain an invalid record"
        )
    if (
        record.status is not EvaluationStatus.ERROR
        or not isinstance(record.resource_id, str)
        or not isinstance(record.resource_type, str)
        or (record.rule_id is not None and not isinstance(record.rule_id, str))
        or not isinstance(record.error_code, str)
        or not record.error_code.strip()
        or not isinstance(record.message, str)
        or not record.message.strip()
        or record.detail_code is not None
        or (record.detail_code is not None and not isinstance(record.detail_code, str))
        or not isinstance(record.error_codes, tuple)
        or any(not isinstance(code, str) for code in record.error_codes)
        or any(not code.strip() for code in record.error_codes)
        or (record.error_codes and record.error_codes[0] != record.error_code)
        or (record.finding is not None and not isinstance(record.finding, Finding))
        or (
            record.finding is not None
            and (
                record.finding.resource_id != record.resource_id
                or record.finding.rule_id != record.rule_id
            )
        )
    ):
        raise RepositorySerializationError("assessment error record is invalid")
    return {
        "resource_id": record.resource_id,
        "resource_type": record.resource_type,
        "rule_id": record.rule_id,
        "status": record.status.value,
        "error_code": record.error_code,
        "message": record.message,
        "detail_code": record.detail_code,
        "error_codes": list(record.error_codes or (record.error_code,)),
        "finding_id": str(record.finding.finding_id) if record.finding else None,
    }
