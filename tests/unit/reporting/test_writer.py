import json
from pathlib import Path

import pytest

from cspm.reporting import ReportDataError, ReportFormatError, ReportWriteError
from cspm.reporting.writer import generate_reports


@pytest.mark.parametrize(
    ("report_format", "filename"),
    [
        ("json", "findings.json"),
        ("html", "report.html"),
        ("markdown", "report.md"),
    ],
)
def test_writer_supports_each_format_and_scan_specific_directory(
    tmp_path, repository_factory, report_format, filename
):
    repository, scan, _, _ = repository_factory()
    output = tmp_path / "custom-reports"

    paths = generate_reports(
        repository, scan.scan_id, formats=report_format, output_dir=output
    )

    assert list(paths) == [report_format]
    assert paths[report_format] == output / str(scan.scan_id) / filename
    assert paths[report_format].is_file()
    if report_format == "json":
        assert json.loads(paths[report_format].read_text(encoding="utf-8"))["scan"][
            "scan_id"
        ] == str(scan.scan_id)


def test_writer_all_formats_and_default_directory(
    tmp_path, monkeypatch, repository_factory
):
    repository, scan, _, _ = repository_factory()
    monkeypatch.chdir(tmp_path)

    paths = generate_reports(repository, scan.scan_id)

    assert list(paths) == ["json", "html", "markdown"]
    assert paths["json"] == Path("reports") / str(scan.scan_id) / "findings.json"
    assert paths["html"].name == "report.html"
    assert paths["markdown"].name == "report.md"
    assert all(path.is_file() for path in paths.values())


def test_writer_normal_publication_tracks_the_published_file_identity(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_cleanup = writer._cleanup_owned
    observed = []

    def verify_identity(files, description):
        if description == "temporary report":
            for _, expected_identity in files:
                observed.append(expected_identity)
                assert writer._file_identity(output_path) == expected_identity
        return original_cleanup(files, description)

    output_path = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
    monkeypatch.setattr(writer, "_cleanup_owned", verify_identity)

    paths = generate_reports(
        repository, scan.scan_id, formats="json", output_dir=tmp_path / "reports"
    )

    assert paths["json"] == output_path
    assert output_path.is_file()
    assert observed


def test_writer_rejects_unsupported_format_before_creating_output(
    tmp_path, repository_factory
):
    repository, scan, _, _ = repository_factory()
    output = tmp_path / "reports"

    with pytest.raises(ReportFormatError, match="unsupported report format"):
        generate_reports(repository, scan.scan_id, formats="pdf", output_dir=output)
    assert not output.exists()


def test_writer_reports_unwritable_destination(tmp_path, repository_factory):
    repository, scan, _, _ = repository_factory()
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("existing user file", encoding="utf-8")

    with pytest.raises(ReportWriteError, match="could not write report files"):
        generate_reports(repository, scan.scan_id, output_dir=blocker)
    assert blocker.read_text(encoding="utf-8") == "existing user file"


def test_writer_does_not_overwrite_an_existing_file(tmp_path, repository_factory):
    repository, scan, _, _ = repository_factory()
    output = tmp_path / "reports"
    scan_dir = output / str(scan.scan_id)
    scan_dir.mkdir(parents=True)
    existing = scan_dir / "findings.json"
    existing.write_text("keep this unrelated content", encoding="utf-8")

    with pytest.raises(ReportWriteError, match="never overwritten"):
        generate_reports(repository, scan.scan_id, formats="json", output_dir=output)
    assert existing.read_text(encoding="utf-8") == "keep this unrelated content"
    assert sorted(path.name for path in scan_dir.iterdir()) == ["findings.json"]


def test_writer_rolls_back_published_files_after_a_later_write_failure(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    output = tmp_path / "reports"
    import cspm.reporting.writer as writer

    original_link = writer.os.link
    calls = 0

    def fail_second_link(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated publication failure")
        return original_link(source, destination)

    monkeypatch.setattr(writer.os, "link", fail_second_link)

    with pytest.raises(ReportWriteError):
        generate_reports(repository, scan.scan_id, output_dir=output)

    scan_dir = output / str(scan.scan_id)
    assert list(scan_dir.iterdir()) == []


def test_writer_rollback_preserves_replacement_file(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_link = writer.os.link
    calls = 0

    def fail_later_after_replacing(source, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            original_link(source, destination)
            return
        target = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
        target.unlink()
        target.write_text("replacement owned by another process", encoding="utf-8")
        raise OSError("simulated later publication failure")

    monkeypatch.setattr(writer.os, "link", fail_later_after_replacing)
    with pytest.raises(ReportWriteError, match="cleanup also failed"):
        generate_reports(repository, scan.scan_id, output_dir=tmp_path / "reports")

    replacement = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
    assert replacement.read_text(encoding="utf-8") == (
        "replacement owned by another process"
    )


def test_writer_rollback_tolerates_published_file_removed_externally(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_link = writer.os.link
    calls = 0

    def fail_later_after_removing(source, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            original_link(source, destination)
            return
        target = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
        target.unlink()
        raise OSError("simulated later publication failure")

    monkeypatch.setattr(writer.os, "link", fail_later_after_removing)
    with pytest.raises(ReportWriteError, match="could not write report files"):
        generate_reports(repository, scan.scan_id, output_dir=tmp_path / "reports")

    assert list((tmp_path / "reports" / str(scan.scan_id)).iterdir()) == []


def test_writer_identity_check_failure_leaves_published_file_untouched(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_link = writer.os.link
    original_identity = writer._file_identity
    calls = 0
    target_checks = 0

    def fail_second_link(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated later publication failure")
        return original_link(source, destination)

    def fail_target_identity(path):
        nonlocal target_checks
        if path.name == "findings.json":
            target_checks += 1
            if target_checks > 1:
                raise OSError("simulated rollback identity-check failure")
        return original_identity(path)

    monkeypatch.setattr(writer.os, "link", fail_second_link)
    monkeypatch.setattr(writer, "_file_identity", fail_target_identity)
    with pytest.raises(ReportWriteError, match="cleanup also failed"):
        generate_reports(repository, scan.scan_id, output_dir=tmp_path / "reports")

    published = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
    assert published.is_file()


def test_writer_rejects_temporary_source_replaced_before_link(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_link = writer.os.link
    replaced_sources = []

    def replace_source_then_link(source, destination):
        source_path = Path(source)
        replacement_path = source_path.with_suffix(".replacement")
        replacement_path.write_text("unexpected replacement", encoding="utf-8")
        source_path.unlink()
        replacement_path.replace(source_path)
        replaced_sources.append(source_path)
        original_link(source_path, destination)

    monkeypatch.setattr(writer.os, "link", replace_source_then_link)
    with pytest.raises(
        ReportWriteError, match="could not verify report publication ownership"
    ):
        generate_reports(
            repository,
            scan.scan_id,
            formats="json",
            output_dir=tmp_path / "reports",
        )

    published = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
    assert published.read_text(encoding="utf-8") == "unexpected replacement"
    assert replaced_sources[0].read_text(encoding="utf-8") == (
        "unexpected replacement"
    )
    assert replaced_sources[0].is_file()


def test_writer_post_link_identity_inspection_failure_preserves_target(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    original_identity = writer._file_identity

    def fail_target_identity(path):
        if path.name == "findings.json":
            raise OSError("simulated post-link identity failure")
        return original_identity(path)

    monkeypatch.setattr(writer, "_file_identity", fail_target_identity)
    with pytest.raises(
        ReportWriteError, match="could not verify report publication ownership"
    ):
        generate_reports(
            repository,
            scan.scan_id,
            formats="json",
            output_dir=tmp_path / "reports",
        )

    published = tmp_path / "reports" / str(scan.scan_id) / "findings.json"
    assert published.is_file()


def test_writer_temporary_identity_failure_leaves_unverified_temp_untouched(
    tmp_path, repository_factory, monkeypatch
):
    repository, scan, _, _ = repository_factory()
    import cspm.reporting.writer as writer

    def fail_fstat(_descriptor):
        raise OSError("simulated temporary identity failure")

    with monkeypatch.context() as scoped_monkeypatch:
        scoped_monkeypatch.setattr(writer.os, "fstat", fail_fstat)
        with pytest.raises(ReportWriteError, match="cleanup also failed"):
            generate_reports(
                repository,
                scan.scan_id,
                formats="json",
                output_dir=tmp_path / "reports",
            )

    scan_dir = tmp_path / "reports" / str(scan.scan_id)
    assert len(list(scan_dir.glob(".cspm-report-*.tmp"))) == 1
    assert not (scan_dir / "findings.json").exists()


def test_writer_rejects_non_uuid_scan_path_before_writing(tmp_path, repository_factory):
    repository, _, _, _ = repository_factory()
    output = tmp_path / "reports"

    with pytest.raises(ReportDataError, match="scan_id must be a UUID"):
        generate_reports(repository, "..\\outside", output_dir=output)
    assert not output.exists()
