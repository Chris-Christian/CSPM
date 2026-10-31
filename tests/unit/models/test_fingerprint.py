import re

import pytest

from cspm.models.fingerprint import generate_fingerprint


def test_fingerprint_is_deterministic_and_versioned() -> None:
    fingerprint = generate_fingerprint("S3-001", "s3_bucket", "bucket-123")

    assert generate_fingerprint("S3-001", "s3_bucket", "bucket-123") == fingerprint
    assert re.fullmatch(r"v1:[0-9a-f]{64}", fingerprint)


def test_fingerprint_is_deterministic_for_unicode_inputs() -> None:
    fingerprint = generate_fingerprint("règle-1", "bücket", "資源-123")

    assert generate_fingerprint("règle-1", "bücket", "資源-123") == fingerprint


def test_fingerprint_distinguishes_unicode_inputs() -> None:
    first = generate_fingerprint("règle-1", "bucket", "資源-123")
    second = generate_fingerprint("règle-1", "bucket", "資源-124")

    assert first != second


def test_fingerprint_handles_unpaired_surrogate() -> None:
    fingerprint = generate_fingerprint("S3-001", "s3_bucket", "bucket-\ud800")

    assert re.fullmatch(r"v1:[0-9a-f]{64}", fingerprint)


@pytest.mark.parametrize(
    ("rule_id", "resource_type", "resource_id"),
    [
        ("S3-002", "s3_bucket", "bucket-123"),
        ("S3-001", "iam_role", "bucket-123"),
        ("S3-001", "s3_bucket", "bucket-456"),
    ],
)
def test_fingerprint_changes_when_any_identity_field_changes(
    rule_id: str, resource_type: str, resource_id: str
) -> None:
    changed = generate_fingerprint(rule_id, resource_type, resource_id)
    baseline = generate_fingerprint("S3-001", "s3_bucket", "bucket-123")

    assert changed != baseline


def test_fingerprint_serialization_is_unambiguous() -> None:
    first = generate_fingerprint("ab", "c", "resource")
    second = generate_fingerprint("a", "bc", "resource")

    assert first != second


@pytest.mark.parametrize(
    "values",
    [
        ("", "s3_bucket", "bucket-123"),
        ("S3-001", "  ", "bucket-123"),
        ("S3-001", "s3_bucket", ""),
    ],
)
def test_fingerprint_rejects_blank_inputs(values: tuple[str, str, str]) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        generate_fingerprint(*values)


@pytest.mark.parametrize(
    "values",
    [
        (None, "s3_bucket", "bucket-123"),
        ("S3-001", 1, "bucket-123"),
    ],
)
def test_fingerprint_rejects_non_string_inputs(
    values: tuple[object, object, object],
) -> None:
    with pytest.raises(TypeError, match="must be strings"):
        generate_fingerprint(*values)
