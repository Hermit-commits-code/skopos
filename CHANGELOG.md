# Changelog

## [0.23.1] - 2026-02-19

### Added
- **Expanded Typosquatting Targets**: Increased the default high-value package list used by the typosquatting engine.
- **Integrations Scaffold**: Added opt-in adapters for external enrichment (Snyk and Socket) with safe, no-network defaults.
- **Offline Snyk Enrichment**: Support for a local Snyk-style JSON feed and a CLI loader (`skopos integrations load-snyk`) to include offline vulnerability data in audits.
- **Demo Script**: Added a repository-only demo script showing offline enrichment; intentionally excluded from sdist packages.

### Changed
- **Docs**: README and integration docs updated with quick-start instructions and security caveats.

### Notes
- Adapters are disabled by default and require explicit configuration in `~/.skopos/config.toml` before any network activity.

## [0.23.0] - 2026-02-18

## [0.22.1] - 2026-02-17

### Changed
- **Identity Heuristics**: Fixed `KeyError` in author reputation checks and improved brand-jacking detection.
- **Namespace**: Finalized migration from `spectr` to `skopos` in all core logic.

## [0.22.0] - 2026-02-17

### Added

- **Giant's Immunity**: Established projects (>50 releases) are now exempt from metadata-gap flagging.
- **Interactive Audit**: The `audit` command now prompts users to whitelist high-risk packages.
- **Levenshtein Engine**: Integrated a more robust typosquatting detection algorithm.

### Changed

- **Architecture**: Consolidated `similarity.py` and `interceptor.py` into the core `checker` modules.
- **UI**: Refined forensic reports to correctly display PASS/FAIL status for typosquatting.

### Removed

- **Redundancy**: Deleted `src/skopos/similarity.py` and `src/skopos/interceptor.py`.

## [0.21.0] - 2026-02-16

### Added

- **The Persistence Layer**: Integrated SQLite-based audit caching (`~/.skopos/audit_cache.db`).
- **Sandbox v2**: Implemented `RestrictedPython` for safe metadata snippet execution.

## [0.20.0] - 2026-02-16

### Added

- **Weighted Scoring**: Initial implementation of the 0-100 risk scoring algorithm.
- **Identity Heuristics**: Added detection for missing author/email metadata.

## [0.19.0] - 2026-02-16

### Added

- **Persistence Layer**: Integrated SQLite-based audit caching in `~/.skopos/audit_cache.db`.
- **Performance**: Near-instantaneous re-audits for cached package versions (24-hour TTL).
- **Stateful Memory**: Skopos now remembers forensic scores across different terminal sessions.

## [0.18.0] - 2026-02-15

### Added

- **The Brain**: Implemented the SkoposScore weighted 0-100 risk engine.
- **Giant's Immunity**: Prevention of false positives on legacy giants like NumPy/Pandas.
- **Fix**: Resolved integer unpacking TypeErrors in recursive loops.

## [0.17.0] - 2026-02-15

### Added

- **Metadata Plus**: Enhanced forensic metadata extraction for deeper package insights.
- Refined Reputation heuristics for more accurate "Days Old" calculations.

## [0.16.0] - 2026-02-15

### Added

- **Recursive Auditor**: Added `--recursive` and `--max-depth` to scan dependency trees.
- **Deep Scanning**: Improved payload analysis for nested sub-dependencies.

## [0.15.0] - 2026-02-15

### Added

- **The TUI & Forensics**: Rich-powered Terminal UI with animated spinners.
- **Forensics**: Color-coded status tables for human-readable audits.

## [0.14.0] - 2026-02-15

### Added

- **Automated Test Suite**: Integrated CI-ready testing for forensic heuristics.
- Refactored core logic into `checker_logic.py` for modularity.

## [0.13.0] - 2026-02-15

### Added

- **Update Engine**: Automated version checking via PyPI API.
- **Documentation**: Finalized shell hook installation guides.

## [0.12.0] - 2026-02-15

### Added

- **JSON Support**: Implemented `--json` flag for machine-readable output.
- **Forensic Metadata**: Expansion of structural analysis metrics (sdist size).

## [0.11.0] - 2026-02-15

### Added

- **The Forensic Update**: Broadening of the heuristic suite.
- **Typosquatting Engine**: Local Levenshtein distance checks for high-value targets.

## [0.10.0] - 2026-02-15

### Added

- **Identity & Structure**: Detecting "Skeleton" packages and brand-jacking.
- **Rebranding**: Finalized migration from "Ghost" to **Skopos**.

## [0.9.0] - 2026-02-15

### Added

- **The Identity Update**: Implementation of author email verification heuristics.

## [0.8.2] - 2026-02-15

### Added

- Navigation polish and terminal output formatting improvements.

## [0.8.1] - 2026-02-15

### Added

- **Case Study**: Documentation of "Inflated Trust" attack vectors.

## [0.8.0] - 2026-02-15

### Added

- **The Integration Release**: Automated shell hook (`pip-install`) installer.

## [0.6.0] - 2026-02-15

### Added

- **Deep Analysis Engine**: High-download/low-age "inflated trust" flagging.

## [0.5.0] - 2026-02-15

### Added

- **The Trust Update**: Initial implementation of the `~/.skopos-whitelist` system.

## [0.4.0] - 2026-02-15

### Added

- Similarity engine using `difflib` for typosquatting detection.

## [0.3.0] - 2026-02-14

### Added

- Multi-Package Support for interception loops.
- **The Kill Switch**: `skopos-off` command to remove shell aliases.

## [0.2.0] - 2026-02-14

### Added

- `skopos-init` command to generate shell interception logic.

## [0.1.0] - 2026-02-14

### Added

- Initial project release with 72-hour age-gating policy.

- **The Integration Release**: Automated shell hook (`pip-install`) installer.

## [0.6.0] - 2026-02-15

### Added

- **Deep Analysis Engine**: High-download/low-age "inflated trust" flagging.

## [0.5.0] - 2026-02-15

### Added

- **The Trust Update**: Initial implementation of the `~/.skopos-whitelist` system.

## [0.4.0] - 2026-02-15

### Added

- Similarity engine using `difflib` for typosquatting detection.

## [0.3.0] - 2026-02-14

### Added

- Multi-Package Support for interception loops.
- **The Kill Switch**: `skopos-off` command to remove shell aliases.

## [0.2.0] - 2026-02-14

### Added

- `skopos-init` command to generate shell interception logic.

## [0.1.0] - 2026-02-14

### Added

- Initial project release with 72-hour age-gating policy.
