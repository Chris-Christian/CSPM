"""Utilities for safely normalizing AWS response data into model metadata."""

import math
from collections.abc import Mapping
from datetime import UTC, date, datetime
from typing import Any


def normalize_json(value: Any) -> Any:
    """Convert AWS response values to JSON-compatible values without repr fallbacks."""
    return _normalize_json(value, set())


def _normalize_json(value: Any, active_containers: set[int]) -> Any:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("AWS response contains a non-finite number")
        return value
    if isinstance(value, datetime):
        aware_value = (
            value if value.utcoffset() is not None else value.replace(tzinfo=UTC)
        )
        return aware_value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("AWS response contains a non-string object key")
        container_id = id(value)
        if container_id in active_containers:
            raise ValueError("AWS response contains cyclic containers")
        active_containers.add(container_id)
        try:
            return {
                key: _normalize_json(item, active_containers)
                for key, item in value.items()
            }
        finally:
            active_containers.remove(container_id)
    if isinstance(value, (list, tuple)):
        container_id = id(value)
        if container_id in active_containers:
            raise ValueError("AWS response contains cyclic containers")
        active_containers.add(container_id)
        try:
            return [_normalize_json(item, active_containers) for item in value]
        finally:
            active_containers.remove(container_id)
    raise ValueError(f"Unsupported AWS response value: {type(value).__name__}")


def normalize_tags(tags: object) -> dict[str, str]:
    """Normalize AWS tag lists or mappings to the Resource tags contract."""
    if tags is None:
        return {}
    if isinstance(tags, Mapping):
        pairs = list(tags.items())
    elif isinstance(tags, list):
        pairs = []
        for item in tags:
            if not isinstance(item, dict):
                raise ValueError("AWS tag entry was not an object")
            pairs.append((item.get("Key"), item.get("Value")))
    else:
        raise ValueError("AWS tags were not a mapping or tag list")

    normalized: dict[str, str] = {}
    for key, value in pairs:
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("AWS tag keys and values must be strings")
        normalized[key] = value
    return normalized
