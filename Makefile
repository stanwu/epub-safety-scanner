.PHONY: test lint format check install clean skill

PYTHON := .venv/bin/python
PIP := .venv/bin/pip

## Run unit tests
test:
	$(PYTHON) -m pytest test_epub_safety_scanner.py -v

## Run linters (ruff + bandit + mypy)
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m bandit -c pyproject.toml -r epub_safety_scanner.py
	$(PYTHON) -m mypy epub_safety_scanner.py

## Auto-format code
format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

## Run all checks (lint + test)
check: lint test

## Install dev dependencies
install:
	$(PIP) install -r requirements-dev.txt
	$(PYTHON) -m pre_commit install

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
