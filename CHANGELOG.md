# Changelog

## All notable changes to this project will be documented in this file

## [0.11.0] - 2026-02-15

### Added

- **Typosquatting Engine**: Local Levenshtein distance check for high-value targets (requests, boto3, etc.).
- **uv Integration**: Full support for `uv` and `uvx` workflows.
- **Management CLI**: New entry points `spectr-init` (setup) and `spectr-off` (kill-switch).
- **Failure Reporting**: Granular feedback showing exactly which forensic check failed.

### Changed

- **Rebranding**: Complete transition from "Ghost" to **Spectr**.
- **Package Structure**: Moved to a standard `src/` layout for better distribution.
- **Security Posture**: Switched to a "Default Deny" model using `all()` validation for heuristics.

### Fixed

- Resolved `NameError` in CLI when running administrative flags.
- Fixed variable scope for PyPI metadata during forensic analysis.

## [0.10.0] - 2026-02-15

### Changed

- **Rebranding**: Complete migration from 'Ghost' to 'Spectr'.
- **File Structure**: Transitioned to `src/spectr/` layout for better package management.
- **Whitelist Migration**: Trusted packages now managed in `~/.spectr-whitelist`.

### Added

- **Structural Analysis Engine**: Detecting 'Skeleton' or 'Ghost' packages by analyzing source distribution (sdist) size.
- **Integrity Signing**: New `spectr sign` command to authorize whitelist changes.

## [0.9.0] - 2026-02-15

### Added

- **Identity Verification Engine**: New heuristic to detect "Brand-Jacking" (e.g., packages starting with 'google' or 'aws' maintained by generic gmail/outlook accounts).
- **Consolidated Metadata Check**: Integrated identity, reputation, and velocity into a unified security validation chain.
- **Future-Proofing**: Added CLI placeholders for `uv` backend integration.- **Identity Verification Engine**: New heuristic to detect "Brand-Jacking" (e.g., packages starting with 'google' or 'aws' maintained by generic gmail/outlook accounts).
- **Consolidated Metadata Check**: Integrated identity, reputation, and velocity into a unified security validation chain.
- **Future-Proofing**: Added CLI placeholders for `uv` backend integration.

## [0.8.1] - 2026-02-15

### Added

- **Formal Case Study**: Documentation of the "Inflated Trust" attack and Ghost's defensive response.

## [0.8.0] - 2026-02-15

### Added

- **Seamless Integration**: Added `--install-hook` flag to automatically configure shell aliases (`pip-install`).
- **Idempotent Setup**: The hook installer now detects existing configurations to prevent duplicate entries in `.bashrc` or `.zshrc`.
- **Shell Awareness**: Logic to automatically differentiate between Bash and Zsh environments.
  es (`pip-install`).
- **Idempotent Setup**: The hook installer now detects existing configurations to prevent duplicate entries in `.bashrc` or `.zshrc`.
- **Shell Awareness**: Logic to automatically differentiate between Bash and Zsh environments.

## [0.7.0] - 2026-02-15

### Added

- **Configuration Hardening**: Moved whitelist to `~/.ghost-whitelist` to prevent project-level injection.
- **Integrity Tripwire**: Implemented SHA-256 signature verification for the whitelist to detect unauthorized modifications.
- **Administrative CLI**: Added `--sign` flag to allow users to re-authorize the whitelist.
- **Network Defense**: Implemented professional User-Agent headers and enforced SSL verification.

## [0.6.0] - 2026-02-15

### Added

- **Reputation Engine**: Flags packages with high download counts but very young age (checks for inflated trust).
- **Velocity Check**: Detects "release spraying" by flagging packages with excessive version updates in a short window.
- **Modern Datetime Handling**: Updated UTC logic to be compliant with Python 3.12+ (removing deprecated `utcnow`).

### Fixed

- **PyPI Data Flow**: Refactored `checker.py` to use a single API call per package for better performance and reliability.

## [0.5.0] - 2026-02-15

### Added

- **Whitelisting System**: Users can now trust specific packages via a `.ghost-whitelist` file.
- **Auto-Initialization**: Ghost now automatically creates a default whitelist file with instructions if one is missing.
- **Comment Support**: The whitelist parser now ignores lines starting with `#`.

[0.4.0] - 2026-02-15

### Added

- **Typo-Squatting Detection**: Introduced a similarity engine using `difflib`.
- **Similarity Threshold**: Established a **0.85** match requirement against a "Safe List" of popular packages.
- **Improved CLI Logic**: Reordered `main()` execution to ensure arguments are parsed before security checks are triggered.
  - **Similarity Threshold**: Established a **0.85** match requirement against a "Safe List" of popular packages.
- **Improved CLI Logic**: Reordered `main()` execution to ensure arguments are parsed before security checks are triggered.

### Security

- Prevented potential malicious installations by blocking execution on high-similarity name matches.

[0.3.0] - 2026-02-14

### Added

- Multi-Package Support: The interceptor now loops through all command-line arguments. This ensures that every package
  in a bulk command (e.g., pip install requests pandas) is verified by Ghost.
- The "Kill Switch": Introduced the ghost-off command to safely unset shell aliases and restore the default behavior of
  pip and uv.
- Package Manager Consistency: Added multi-package looping logic to the uv wrapper to match the pip implementation.

### Fixed

- Shell Interpolation: Resolved a command not found error by correctly using ${@:2} for argument slicing in Bash.
- Syntax Robustness: Added necessary spacing within [[...]] blocks to ensure compatibility with strict POSIX/Bash shells.
- Flag Filtering: Improved the loop logic to automatically skip arguments starting with a dash (e.g., --upgrade, -r), preventing Ghost from trying to "check" non-package flags.

### Security

    Atomic Failure: If any single package in a multi-package install fails the Ghost check, the entire installation
    command is aborted, preventing partial "poisoning" of the environment.

## [0.2.0] - 2026-02-14

### Added

- `ghost-init` command to generate shell interception logic for Bash/Zsh.
- Automated blocking for `pip install` and `uv pip install`.
- `textwrap.dedent` implementation to ensure shell-safe formatting.

### Fixed

- Resolved Bash syntax error where `eval` failed due to incorrect indentation in the generated shell function.
- Prevented infinite loops in shell functions by using the `command` prefix.

## [0.1.0] - 2026-02-14

### Added

- Initial project structure using `src` layout.
- `pyproject.toml` configuration for professional packaging and CLI entry points.
- Core `checker_logic` module with PyPI JSON API integration for age-gating.
- CLI entry point `ghost` for manual package verification.
- Support for `uv` package manager and PEP 668 compliance.

### Fixed

- Resolved `ModuleNotFoundError` by correctly implementing relative imports between `checker` and `checker_logic`.

### Security

- Implemented 72-hour age-gating policy to prevent AI-package hallucination attacks (Slopsquatting).
