"""Stable identity fingerprints for findings."""

import hashlib
import json


def generate_fingerprint(rule_id: str, resource_type: str, resource_id: str) -> str:
    """Return a versioned SHA-256 fingerprint for a rule/resource identity."""
    values = (rule_id, resource_type, resource_id)
    if any(not isinstance(value, str) for value in values):
        raise TypeError("fingerprint inputs must be strings")
    if any(not value.strip() for value in values):
        raise ValueError("fingerprint inputs must not be empty or whitespace-only")

    canonical_identity = json.dumps(
        ["v1", rule_id, resource_type, resource_id],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    digest = hashlib.sha256(canonical_identity).hexdigest()
    return f"v1:{digest}"
