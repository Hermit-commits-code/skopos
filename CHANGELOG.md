# Changelog

## All notable changes to this project will be documented in this file

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
