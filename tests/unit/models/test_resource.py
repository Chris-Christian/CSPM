import json
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from cspm.models.resource import Resource


def make_resource(**overrides: object) -> Resource:
    values: dict[str, object] = {
        "scan_id": uuid4(),
        "resource_id": "bucket-123",
        "resource_type": "s3_bucket",
        "region": "us-east-1",
    }
    values.update(overrides)
    return Resource(**values)


def test_resource_valid_construction() -> None:
    resource = make_resource()

    assert isinstance(resource.scan_id, UUID)
    assert resource.raw_metadata == {}
    assert resource.tags == {}


@pytest.mark.parametrize(
    "missing_field", ["scan_id", "resource_id", "resource_type", "region"]
)
def test_resource_requires_fields(missing_field: str) -> None:
    values: dict[str, object] = {
        "scan_id": uuid4(),
        "resource_id": "bucket-123",
        "resource_type": "s3_bucket",
        "region": "us-east-1",
    }
    del values[missing_field]

    with pytest.raises(ValidationError):
        Resource(**values)


def test_resource_rejects_invalid_uuid() -> None:
    with pytest.raises(ValidationError):
        make_resource(scan_id="not-a-uuid")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resource_id", ""),
        ("resource_id", "  "),
        ("resource_type", "\t"),
        ("region", "  "),
    ],
)
def test_resource_rejects_blank_required_strings(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make_resource(**{field: value})


@pytest.mark.parametrize(
    "metadata",
    [
        {"value": object()},
        {"value": (1, 2)},
        {1: "non-string key"},
        {"nested": {False: "non-string key"}},
        {"value": float("nan")},
        {"value": float("inf")},
    ],
)
def test_resource_rejects_non_json_metadata(metadata: object) -> None:
    with pytest.raises(ValidationError):
        make_resource(raw_metadata=metadata)


def test_resource_rejects_self_referencing_metadata_list() -> None:
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)

    with pytest.raises(ValidationError, match="cyclic references"):
        make_resource(raw_metadata={"items": cyclic_list})


def test_resource_rejects_self_referencing_metadata_dictionary() -> None:
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = cyclic_dict

    with pytest.raises(ValidationError, match="cyclic references"):
        make_resource(raw_metadata={"nested": cyclic_dict})


def test_resource_accepts_repeated_non_cyclic_metadata_reference() -> None:
    shared_list = [1, {"enabled": True}]

    resource = make_resource(
        raw_metadata={"first": shared_list, "second": shared_list}
    )

    assert resource.raw_metadata["first"] == shared_list
    assert resource.raw_metadata["second"] == shared_list


@pytest.mark.parametrize(
    "tags",
    [
        {1: "value"},
        {"key": 1},
        {"key": None},
    ],
)
def test_resource_rejects_non_string_tag_keys_or_values(tags: object) -> None:
    with pytest.raises(ValidationError):
        make_resource(tags=tags)


def test_resource_default_dictionaries_are_independent() -> None:
    first = make_resource()
    second = make_resource()
    first.raw_metadata["owner"] = "security"
    first.tags["environment"] = "test"

    assert second.raw_metadata == {}
    assert second.tags == {}


def test_resource_json_round_trip() -> None:
    resource = make_resource(
        raw_metadata={
            "enabled": True,
            "count": 2,
            "ratio": 1.5,
            "nested": [None, "text", {"key": "value"}],
        },
        tags={"environment": "test"},
    )

    restored = Resource.model_validate_json(resource.model_dump_json())

    assert restored == resource
    assert json.loads(resource.model_dump_json())["tags"] == {"environment": "test"}
