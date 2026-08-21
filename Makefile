.PHONY: help install dev test lint clean run

help:
	@echo "Targets: install dev test lint clean run"

install:
	pip install -e ".[dev]"

dev:
	python3 -m venv .venv
	source .venv/bin/activate && pip install -e ".[dev]"

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check .

clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .mypy_cache

run:
	./cveli "$@"
