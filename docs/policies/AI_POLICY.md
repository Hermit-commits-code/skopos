# AI Assistance Policy

This project used generative AI tools to assist with code changes, tests, documentation, and repository maintenance. This document explains how AI was used, what review steps were taken, and known limitations.

1. Summary

- AI was used to accelerate refactoring, create and consolidate tests, generate helper scripts, and draft documentation.
- All AI-generated content was reviewed, edited, and approved by a human maintainer before being committed.

2. How AI Was Used

- Refactoring: renaming modules and updating imports to `skopos`.
- Tests: adding new unit and integration tests and consolidating duplicates.
- Scripts: creating reproducible test/run helpers such as `scripts/run_coverage.sh` and badge generator utilities.
- Docs: drafting `CONTRIBUTING.md`, `RELEASE_CHECKLIST.md`, and parts of `README.md`.

3. Human Review

- Every change produced with AI assistance was validated by the repository maintainer: tests were run locally, output was inspected, and edits were iterated until passing.
- The maintainer is responsible for final decisions about behavior, security, and release.

4. Limitations and Known Risks

- AI can make reasonable but imperfect suggestions. Relying solely on AI without human verification may introduce errors or security regressions.
- The AI does not have access to private credentials, build servers, or external sensitive resources during the edit process.

5. Contact & Disclosure

If you have questions about specific changes that were AI-assisted, open an issue or contact the maintainer.
