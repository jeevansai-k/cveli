.PHONY: help install dev test cov lint typecheck security snapshots smoke clean run

MYPY_TARGETS = config utils/http.py utils/color.py core/models.py core/safety.py \
	core/dork_policy.py core/dork_templates.py core/social_platforms.py \
	core/merge.py core/msf \
	services/exploitdb.py services/dorks.py services/msf_template.py \
	services/projects.py services/audit.py services/jobs.py sources/exploitdb.py \
	storage/migrations.py storage/system_repositories.py \
	storage/exploit_repository.py storage/research_repositories.py

help:
	@echo "Targets: install dev test cov lint typecheck security snapshots smoke clean run"

install:
	pip install -e ".[dev]"

dev:
	python3 -m venv .venv
	.venv/bin/pip install -e ".[dev]"

test:
	.venv/bin/pytest

cov:
	.venv/bin/pytest --cov --cov-report=term-missing --cov-fail-under=80

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .

typecheck:
	.venv/bin/mypy $(MYPY_TARGETS)

security:
	.venv/bin/bandit -q -r cli core services sources storage config utils -ll
	.venv/bin/pip-audit --skip-editable

snapshots:
	.venv/bin/pytest tests/test_theme_ui.py --snapshot-update

smoke:
	.venv/bin/pytest -m live

clean:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .mypy_cache .coverage

run:
	./cveli
