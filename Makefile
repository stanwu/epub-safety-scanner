.PHONY: test lint format check install clean skill

## Run unit tests
test:
	uv run pytest test_epub_safety_scanner.py -v

## Run linters (ruff + bandit + mypy)
lint:
	uv run ruff check .
	uv run bandit -c pyproject.toml -r epub_safety_scanner.py
	uv run mypy epub_safety_scanner.py

## Auto-format code
format:
	uv run ruff format .
	uv run ruff check --fix .

## Run all checks (lint + test)
check: lint test

## Install dev dependencies
install:
	uv sync --all-groups
	uv run pre-commit install --install-hooks

## Package claude.ai skill as ZIP
skill:
	cp epub_safety_scanner.py skills/scan-epub/epub_safety_scanner.py
	cd skills && zip -r ../scan-epub-skill.zip scan-epub/
	rm skills/scan-epub/epub_safety_scanner.py
	@echo "Created scan-epub-skill.zip"

## Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
