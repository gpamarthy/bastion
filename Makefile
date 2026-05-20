.PHONY: help install lint format typecheck test test-unit test-transport test-integration test-adversarial benchmark coverage clean

PYTHON  ?= python3
VENV    ?= .venv
PIP     := $(VENV)/bin/pip
PY      := $(VENV)/bin/python
RUFF    := $(VENV)/bin/ruff
MYPY    := $(VENV)/bin/mypy
PYTEST  := $(VENV)/bin/pytest

help:
	@echo "Targets:"
	@echo "  install            create venv and install dev deps"
	@echo "  lint               ruff check + format check"
	@echo "  format             ruff format (write)"
	@echo "  typecheck          mypy --strict on src/"
	@echo "  test               full pytest"
	@echo "  test-unit          tests/unit only"
	@echo "  test-transport     tests/transport only"
	@echo "  test-integration   tests/integration only"
	@echo "  test-adversarial   labeled attack corpus only"
	@echo "  benchmark          run the detection benchmark on the corpus"
	@echo "  coverage           pytest with coverage report"
	@echo "  clean              remove venv + caches"

install: $(VENV)/.installed

$(VENV)/.installed: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	touch $(VENV)/.installed

lint: install
	$(RUFF) check src tests examples scripts
	$(RUFF) format --check src tests examples scripts

format: install
	$(RUFF) check --fix src tests examples scripts
	$(RUFF) format src tests examples scripts

typecheck: install
	$(MYPY) src

test: install
	$(PYTEST) -q

test-unit: install
	$(PYTEST) -q tests/unit

test-transport: install
	$(PYTEST) -q tests/transport

test-integration: install
	$(PYTEST) -q tests/integration

test-adversarial: install
	$(PYTEST) -q -m adversarial

benchmark: install
	$(PY) scripts/benchmark.py

coverage: install
	$(PYTEST) --cov=bastion --cov-branch --cov-report=term-missing --cov-report=xml

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache .mypy_cache build dist .coverage coverage.xml htmlcov *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
