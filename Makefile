
.PHONY: test test-all lint format install

test: test-all

test-all:
	uv run pytest packages/ -v --tb=short
lint:
	uv run ruff check packages/

format:
	uv run ruff format packages/

install:
	uv sync --all-packages

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +