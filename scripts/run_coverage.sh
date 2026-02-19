#!/usr/bin/env bash
set -euo pipefail

# Run tests with coverage and produce terminal + XML reports
VENV=".venv_test"
python -m venv "$VENV"
. "$VENV/bin/activate"
python -m pip install --upgrade pip
pip install -e .[dev]
pip install pytest-cov

# Run pytest with coverage
pytest --cov=skopos --cov-report=term-missing --cov-report=xml:coverage.xml -q

echo "Coverage report generated: coverage.xml"
