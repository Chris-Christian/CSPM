from datetime import UTC, datetime

import pytest

from cspm.collectors.normalization import normalize_json, normalize_tags


def test_normalize_json_converts_nested_aws_datetime_values() -> None:
    value = {"Created": datetime(2026, 1, 2, tzinfo=UTC), "nested": [1, True, None]}

    assert normalize_json(value) == {
        "Created": "2026-01-02T00:00:00+00:00",
        "nested": [1, True, None],
    }


def test_normalize_json_rejects_unsupported_objects_and_non_string_keys() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        normalize_json(object())
    with pytest.raises(ValueError, match="non-string"):
        normalize_json({1: "invalid"})


def test_normalize_json_handles_naive_datetimes_and_rejects_cycles() -> None:
    assert normalize_json(datetime(2026, 1, 2)).endswith("+00:00")
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cyclic"):
        normalize_json(cyclic)


def test_normalize_json_accepts_repeated_acyclic_references() -> None:
    shared = ["safe"]

    assert normalize_json({"first": shared, "second": shared}) == {
        "first": ["safe"],
        "second": ["safe"],
    }


def test_normalize_tags_accepts_aws_tag_list_and_mapping() -> None:
    assert normalize_tags([{"Key": "env", "Value": "test"}]) == {"env": "test"}
    assert normalize_tags({"env": "test"}) == {"env": "test"}


def test_normalize_tags_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        normalize_tags([{"Key": "env", "Value": 3}])
