````markdown
# Contributing and Release Guide

Thank you for contributing to Skopos. This document covers the recommended workflow for development, testing, and releasing to PyPI.

Development
- Create a branch for your change and open a PR against `main`.
- Run tests locally:

```bash
source .venv_test/bin/activate
pytest -q
```

Testing & Packaging (local)
1. Create a clean venv and install dev deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install build pytest pytest-mock pytest-cov
```

2. Run tests and generate coverage:

```bash
pytest --cov=skopos --cov-report=term-missing --cov-report=xml:coverage.xml -q
```

3. Build sdist and wheel:

```bash
python -m build --sdist --wheel -o dist
```

4. Inspect sdist contents:

```bash
tar -tf dist/*.tar.gz
```

UV users — verification
-----------------------

If your environment uses `uv`, verify the packaged tool as follows in a clean environment:

```bash
# install the released package as an `uv` tool (local dev: use editable install or the built wheel)
uv tool install skopos-audit
# refresh uv tool listings if necessary
uvx --refresh skopos
# Try adding a package to ensure the shim intercepts and audits
uv add requests --yes || true
```

Release to PyPI (manual)
- Ensure version bump in `pyproject.toml`.
- Build distribution as above.
- Upload via `twine` (recommended):

```bash
python -m pip install --upgrade twine
python -m twine upload dist/*
```

Notes
- CI: A manual GitHub Actions workflow is provided at `.github/workflows/ci_manual.yml`. It's manual-only (`workflow_dispatch`) so it won't run automatically.
- Badge: Coverage badge generation is described in `docs/TESTING.md` and can be generated locally.

````
