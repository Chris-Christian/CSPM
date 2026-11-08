uv run ruff check .
uv run pytest -m "not integration" --ignore=tests/integration
