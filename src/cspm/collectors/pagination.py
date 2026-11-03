"""Small explicit marker/token pagination helper for AWS list operations."""

from collections.abc import Callable, Mapping
from typing import Any


class PaginationError(RuntimeError):
    """A paginated operation failed after possibly yielding earlier records."""

    def __init__(self, result_key: str, items: list[Any], cause: Exception) -> None:
        super().__init__(f"Pagination failed for {result_key}")
        self.items = items
        self.cause = cause


def collect_pages(
    operation: Callable[..., Mapping[str, Any]], result_key: str, **parameters: Any
) -> list[Any]:
    """Read every page and reject malformed or repeating continuation markers."""
    items: list[Any] = []
    marker: str | None = None
    seen: set[str] = set()
    token_parameter = "NextToken" if result_key == "SecurityGroups" else "Marker"
    while True:
        request = dict(parameters)
        if marker is not None:
            request[token_parameter] = marker
        try:
            response = operation(**request)
        except Exception as exc:
            raise PaginationError(result_key, items, exc) from exc
        if (
            not isinstance(response, Mapping)
            or result_key not in response
            or not isinstance(response[result_key], list)
        ):
            raise PaginationError(
                result_key,
                items,
                ValueError(f"{result_key} returned an invalid paginated response"),
            )
        items.extend(response[result_key])
        truncated = response.get("IsTruncated", False)
        next_marker = (
            response.get("NextToken")
            if token_parameter == "NextToken"
            else response.get("Marker")
        )
        if token_parameter == "Marker" and not truncated:
            break
        if token_parameter == "NextToken" and not next_marker:
            break
        if not isinstance(next_marker, str) or not next_marker or next_marker in seen:
            raise PaginationError(
                result_key,
                items,
                ValueError(f"{result_key} returned an invalid continuation marker"),
            )
        seen.add(next_marker)
        marker = next_marker
    return items
