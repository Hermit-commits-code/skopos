````markdown
## Testing Strategy for Skopos

Recommended (Standard) strategy — pragmatic, professional, and scalable.

1. Unit tests
   - Fast tests for `checker_logic` heuristics, config merging, and utility functions.
   - Aim for high coverage on core logic (70%+ to start).

2. Integration tests
   - Tests that exercise the CLI entrypoint via `python -m skopos.checker` with `PYTHONPATH=src`.
   - Lightweight tests for the `scripts/skopos-uv.sh` shim and PowerShell shim.

3. Packaging checks (manual/local)
   - Build sdist/wheel locally and inspect contents:

```bash
python -m build --sdist --wheel -o dist
tAR -tf dist/*.tar.gz | sed -n '1,200p'
```

Ensure `README.md` and `LICENSE` are included and that repo-only demo files are excluded.

Shim onboarding:

- If you see the shim message `skopos not found; skipping security check` ensure either:
   - you have installed the CLI into your environment (`pip install -e .` inside a venv), or
   - you run the shim from the repository root with `PYTHONPATH="$PWD/src" ./scripts/skopos-uv.sh add <package>`.

The shim prints a short hint when `skopos` isn't available.

UV verification
---------------

If you use the `uv` package manager, validate the release by installing the tool and exercising the shim in a clean environment:

```bash
# install the skopos tool via uv (after publishing or using a built wheel)
uv tool install skopos-audit
uvx --refresh skopos
uv add somepackage --yes || true
```

Coverage badge
---------------

You can generate a simple local coverage badge from `coverage.xml` using the provided script:

```bash
# after running pytest --cov... which writes coverage.xml
python scripts/generate_coverage_badge.py
# badge will be at docs/coverage-badge.svg
```

If you want a hosted badge in `README.md`, use the manual CI workflow (`.github/workflows/ci_manual.yml`) to produce `coverage.xml` and then publish `docs/coverage-badge.svg` somewhere the README can reference (or add a shields.io dynamic badge configured for your coverage host).

4. CI (optional)
   - If desired later, add a minimal smoke CI that builds and installs the wheel into a venv and runs a couple CLI checks. Keep CI off by default unless you want workflows to run on GitHub.

5. When to use TDD
   - Use TDD selectively for high-risk parsing or matching logic.
   - For general development, add tests incrementally focusing on bugs and regressions.

Checklist (short-term)
- [ ] Expand unit tests for `checker_logic` edge cases
- [ ] Add integration tests for `checker` commands and shim behavior (done)
- [ ] Run manual packaging checks before any PyPI publish

````
