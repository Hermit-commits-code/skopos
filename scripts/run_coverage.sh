#!/usr/bin/env bash
set -euo pipefail

# Run tests with coverage and produce terminal + XML reports
# Prefer python3 but fall back to python if available.
if command -v python3 >/dev/null 2>&1; then
	PY=python3
elif command -v python >/dev/null 2>&1; then
	PY=python
else
	echo "Error: python3 or python not found on PATH. Install Python 3.10+ and retry." >&2
	exit 1
fi

VENV=".venv_test"
"$PY" -m venv "$VENV"
. "$VENV/bin/activate"
"$PY" -m pip install --upgrade pip
# Install the project editable and required test tooling into the venv
"$PY" -m pip install -e .
"$PY" -m pip install build pytest-mock pytest-cov

# Run pytest with coverage
pytest --cov=skopos --cov-report=term-missing --cov-report=xml:coverage.xml -q

echo "Coverage report generated: coverage.xml"
