"""Report-format selection and safe, atomic filesystem output."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from cspm.reporting.builder import build_report_data
from cspm.reporting.exceptions import ReportFormatError, ReportWriteError
from cspm.reporting.html_renderer import render_html_report
from cspm.reporting.json_renderer import render_json_report
from cspm.reporting.markdown_renderer import render_markdown_report

if TYPE_CHECKING:
    from cspm.persistence import ScanRepository

_FORMAT_FILENAMES = {
    "json": "findings.json",
    "html": "report.html",
    "markdown": "report.md",
}

_FileIdentity = tuple[int, int]


class _PublicationIdentityError(OSError):
    """Raised when a published path cannot be tied to its source file."""


def _selected_formats(formats: str) -> tuple[str, ...]:
    if not isinstance(formats, str):
        raise ReportFormatError("format must be json, html, markdown, or all")
    normalized = formats.strip().lower()
    if normalized == "all":
        return tuple(_FORMAT_FILENAMES)
    if normalized not in _FORMAT_FILENAMES:
        raise ReportFormatError(
            f"unsupported report format {formats!r}; "
            "choose json, html, markdown, or all"
        )
    return (normalized,)


def _cleanup(paths: list[Path]) -> list[OSError]:
    errors = []
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(exc)
    return errors


def _file_identity(path: Path) -> _FileIdentity:
    """Return the device and file identifier without following symlinks."""
    stat = path.lstat()
    return stat.st_dev, stat.st_ino


def _cleanup_published(
    published: list[tuple[Path, _FileIdentity]],
) -> list[OSError]:
    """Remove only published paths that still identify this operation's files."""
    return _cleanup_owned(published, "published report")


def _cleanup_owned(
    files: list[tuple[Path, _FileIdentity | None]], description: str
) -> list[OSError]:
    """Remove paths only when their current identity matches the recorded one."""
    errors = []
    for path, expected_identity in files:
        if expected_identity is None:
            errors.append(OSError(f"{description} identity unavailable: {path.name}"))
            continue
        try:
            actual_identity = _file_identity(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(exc)
            continue

        if actual_identity != expected_identity:
            errors.append(OSError(f"{description} identity changed: {path.name}"))
            continue

        # Identity check and unlink cannot be made atomic portably (including on
        # Windows). A replacement in this narrow interval remains a residual race.
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(exc)
    return errors


def _write_atomically(directory: Path, contents: dict[str, str]) -> dict[str, Path]:
    temporary_files: list[tuple[Path, _FileIdentity | None]] = []
    published_files: list[tuple[Path, _FileIdentity]] = []
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise OSError("scan report destination is not a regular directory")

        for content in contents.values():
            descriptor, name = tempfile.mkstemp(
                prefix=".cspm-report-", suffix=".tmp", dir=directory
            )
            temporary = Path(name)
            temporary_files.append((temporary, None))
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stat = os.fstat(stream.fileno())
                temporary_files[-1] = (temporary, (stat.st_dev, stat.st_ino))
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())

        output_paths = {
            report_format: directory / _FORMAT_FILENAMES[report_format]
            for report_format in contents
        }
        for (temporary, identity), target in zip(
            temporary_files, output_paths.values(), strict=True
        ):
            # A same-directory hard link publishes the completed file atomically
            # and fails if a prior file already occupies this report filename.
            if identity is None:
                raise _PublicationIdentityError(
                    f"could not verify temporary report identity: {temporary.name}"
                )
            os.link(temporary, target)
            try:
                published_identity = _file_identity(target)
            except OSError as identity_error:
                raise _PublicationIdentityError(
                    f"could not verify published report identity: {target.name}"
                ) from identity_error
            if published_identity != identity:
                raise _PublicationIdentityError(
                    "published report identity does not match its source: "
                    f"{target.name}"
                )
            published_files.append((target, identity))
    except (OSError, UnicodeError) as exc:
        cleanup_errors = _cleanup_published(published_files) + _cleanup_owned(
            temporary_files, "temporary report"
        )
        cleanup_note = "; cleanup also failed" if cleanup_errors else ""
        message = (
            "could not verify report publication ownership; unexpected files were "
            "left untouched"
            if isinstance(exc, _PublicationIdentityError)
            else "could not write report files safely; check destination permissions "
            "and ensure report filenames do not already exist; existing files are "
            "never overwritten"
        )
        raise ReportWriteError(
            f"{message}{cleanup_note}"
        ) from exc

    cleanup_errors = _cleanup_owned(temporary_files, "temporary report")
    if cleanup_errors:
        rollback_errors = _cleanup_published(published_files)
        raise ReportWriteError(
            "report files were published but temporary files could not be removed"
            if not rollback_errors
            else "report publication failed and cleanup was incomplete"
        ) from cleanup_errors[0]
    return output_paths


def generate_reports(
    repository: ScanRepository,
    scan_id: UUID,
    *,
    formats: str = "all",
    output_dir: str | PathLike[str] = "reports",
    generated_at: datetime | None = None,
) -> dict[str, Path]:
    """Prepare a persisted scan report and write the selected output formats.

    Existing report files are never overwritten. The default output is
    ``./reports/<scan_id>/``. The caller must explicitly select one supported
    format or ``all``.
    """
    selected = _selected_formats(formats)
    data = build_report_data(repository, scan_id, generated_at=generated_at)
    renderers = {
        "json": render_json_report,
        "html": render_html_report,
        "markdown": render_markdown_report,
    }
    rendered = {
        report_format: renderers[report_format](data) for report_format in selected
    }
    directory = Path(output_dir) / str(data.scan.scan_id)
    return _write_atomically(directory, rendered)
