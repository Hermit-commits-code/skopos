[![PyPI version](https://img.shields.io/pypi/v/skopos-audit.svg)](https://pypi.org/project/skopos-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# 🛡️ Skopos (v0.23.0)

## Overview

The Zero-Trust Gatekeeper for your Python Environment.

Skopos (Greek for "watcher/lookout") is a high-speed forensic audit tool designed to stop supply-chain attacks before they touch your disk. It sits between you and the internet, ensuring that every `uv add` or `pip install` is safe, verified, and free of "keyword-stuffing" or "brand-jacking" attempts.

## Table of Contents

- [Overview](#overview)
- [Why Skopos?](#why-skopos)
- [Installation](#installation)
	- [For Pip users](#for-pip-users)
	- [For UV users (recommended workflow)](#for-uv-users-recommended-workflow)
- [Automatic Bouncer (Shim)](#automatic-bouncer-shim)
- [Usage & Examples](#usage--examples)
- [Performance](#performance)
- [Forensic Heuristics](#forensic-heuristics)
- [License](#license)

## Why Skopos?

Standard package managers are built for speed, not security. They assume that if a package exists on PyPI, it’s safe to run. They are wrong.

Skopos protects you from:

- **Keyword Stuffing:** Malicious packages like `requests-ultra` or `pip-security-patch`.
- **Brand-jacking:** Fake versions of popular tools (e.g., `google-auth-v2` by an unknown dev).
- **Account Hijacking:** Suddenly active projects after years of silence.
- **Obfuscated Payloads:** Detection of "packed" or encrypted code in package metadata.

## Installation

Choose the workflow that matches your environment. Both approaches are supported — pick one.

### For Pip users

If you prefer standard Python packaging and virtual environments, follow these steps.

Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate
```

Install Skopos into the active environment:

```bash
# During development
pip install -e .

# Or install the released package
pip install skopos-audit
```

Reload your shell if you modified rc files:

```bash
source ~/.bashrc
# or
source ~/.zshrc
```

Quick verification for Pip users:

```bash
which skopos || skopos --version
```

### For UV users (recommended workflow)

If you use `uv` as your package manager, Skopos can be installed as an `uv` tool and hooked into `uv add`.

Install via `uv`:

```bash
uv tool install skopos-audit
```

After installing via `uv`, refresh `uv` so it picks up the new tool entry:

```bash
uvx --refresh skopos
```

If you still want to isolate the CLI into a virtual environment (recommended for development), create and activate one first and then install into it via `pip install -e .`.

Reload your shell and verify the CLI is available:

```bash
source ~/.bashrc || source ~/.zshrc
which skopos || skopos --version
```

## Automatic Bouncer (Shim)

The best way to use Skopos is to let it intercept your commands automatically. This adds a split-second security check whenever you try to add a new dependency.

- Locate the Shim: The script is located in `scripts/skopos-uv.sh`.
- Add to your shell (append to `~/.bashrc` or `~/.zshrc`):

```bash
alias uv='source /path/to/your/skopos/scripts/skopos-uv.sh'
```

Now, when you run `uv add <package>`, Skopos audits the package first. If the score is too high (malicious), the installation is blocked.

## Usage & Examples

You can audit any package without installing it:

```bash
skopos check requests-ultra
```

Example Output (Malicious Package):

```
🔍 Auditing: requests-ultra
------------------------------------------------------------
❌ Typosquatting: FLAG (Match: requests - Keyword stuffing)
⚠️  Identity:      Unknown (New Account / Unverified)
✅ Payload:       Clean (No obfuscation)
------------------------------------------------------------
🚨 SKOPOS SCORE: 120/100 (MALICIOUS)
🚫 Action: Installation Blocked.
```

## Performance

Is it slow? No. Version 0.23.0 removed the heavy `RestrictedPython` sandbox. Skopos now performs "Static Metadata Forensics."

- **Speed:** Checks usually take < 500ms.
- **Safety:** We never execute the code we are auditing. We analyze the "fingerprints" left on PyPI.

## Forensic Heuristics

Skopos uses a weighted scoring system to evaluate risk:

- **Name Similarity:** reqests vs requests (Levenshtein)
- **Keyword Stuffing:** requests-security-update
- **Author Reputation:** Brand new accounts uploading high-value names
- **Entropy Scan:** Encrypted or obfuscated code strings
- **Project Velocity:** "Zombie" projects that suddenly wake up

## License

MIT. Built for developers who value their ssh keys and environment variables.

## Configuration

Skopos supports a user-overridable configuration file at `~/.skopos/config.toml`.
You can bootstrap a template with:

```bash
skopos config init
```

Key configuration options (defaults shown in `etc/skopos_default_config.toml`):

- `targets`: a table mapping high-value package names to a Levenshtein threshold (integer).
- `keyword_extra_chars`: how many extra characters beyond a brand name still trigger a keyword-stuffing flag.
- `scoring_weights`: numeric weights used when aggregating heuristic failures into a final score.

Example `~/.skopos/config.toml` snippet:

```toml
[targets]
requests = 1
openai = 1

keyword_extra_chars = 6

[scoring_weights]
typosquatting = 120
payload_risk = 60
```

If the file is missing or malformed, Skopos falls back to safe defaults so behavior does not change.

## Security Caveats

- **Install-time execution risk:** Some malicious packages execute code during build or installation (for example via `setup.py` or custom build backends in `pyproject.toml`). Skopos inspects metadata and performs static forensics; it does not and must not execute package build or install scripts. As a result, certain installation-time behaviors may not be detectable by static checks alone. Treat Skopos as an added safety layer — not a replacement for isolated analysis of untrusted artifacts.

- **Operational advice:** Never build or install untrusted packages on your primary workstation. If you need to analyze package contents, do so in an isolated VM or container with no secrets and limited network access, and prefer static inspection (unpacking archives and scanning files) over executing any build scripts.

- **Limitations** While `skopos` performs metadata forensics and reduces risk, it is not perfect and may not catch every malicious package or installation-time behavior. Consider Skopos' findings advisory — for high-risk or sensitive packages, perform isolated, in-depth analysis in a disposable VM or container.

## Examples (Good vs Malicious)

These examples show typical output from `uvx skopos check <package>` and what happens when you run `uv add <package>` with the shim installed.

Good package (example):

```bash
$ uvx skopos check requests
🔍 Auditing: requests
------------------------------------------------------------
✅ Typosquatting: PASS
✅ Identity:      PASS (Known maintainer)
✅ Payload:       Clean
------------------------------------------------------------
✅ SKOPOS SCORE: 95/100 (SAFE)
```

The project was previously named `spectr`; some older docs or tools may still reference that name. The same audit behavior is shown here using the legacy command (replace with `skopos` if you have the newer CLI):

```bash
$ uvx spectr check requests
🔍 Auditing: requests
------------------------------------------------------------
✅ Typosquatting: PASS
✅ Identity:      PASS (Known maintainer)
✅ Payload:       Clean
------------------------------------------------------------
✅ SPECTR/SKOPOS SCORE: 95/100 (SAFE)
```

Malicious package (example):

```bash
$ uvx skopos check evil-package
🔍 Auditing: evil-package
------------------------------------------------------------
❌ Typosquatting: FLAG (Match: requests - Keyword match)
⚠️  Identity:      Unknown (New Account / Unverified)
✅ Payload:       Clean
------------------------------------------------------------
🚨 SKOPOS SCORE: 10/100 (MALICIOUS)
```

What happens during `uv add` when the shim is active:

- If the package passes the check, `uv add` proceeds as normal.
- If the package is flagged (non-zero failure), the shim aborts the install and returns a non-zero exit code. Example:

```bash
$ uv add evil-package
[Skopos] Security Gate: Installation aborted due to high risk score.
# installation aborted; package not added
```

## Which commands are wrapped

Skopos provides two ways to intercept package installs:

- The shell shim script `scripts/skopos-uv.sh` (recommended for `uv` users) intercepts `uv add` and `uv run` and performs a pre-install audit.
- The built-in `--install-hook` (via `skopos --install-hook`) installs a minimal `uv()` wrapper into your shell rc which currently intercepts `uv add` before invoking the real `uv` command.

Both approaches are conservative and will skip blocking behavior if the `skopos` CLI is not available on PATH (in which case they print a warning and allow the underlying command to continue).

---

If you want, I can also add annotated screenshots or richer example logs for CI usage and a short section describing how to tune thresholds for your organization.

## Offline Snyk enrichment (quick start)

Skopos can include offline Snyk-like vulnerability feeds as optional enrichment. This is useful for air-gapped environments or when you want a deterministic, local vulnerability dataset.

1. Put a Snyk-style JSON feed on disk (example: `etc/snyk_offline_sample.json`).
2. Register the feed with Skopos:

```bash
# Writes the path into ~/.skopos/config.toml under [integrations.snyk]
skopos integrations load-snyk /full/path/to/snyk_offline.json
```

3. Enable the adapter in your `~/.skopos/config.toml`:

```toml
[integrations.snyk]
enabled = true
offline_file = "/full/path/to/snyk_offline.json"
```

When enabled, Snyk findings from the offline feed will be included in reports and factored into scoring (weight: `snyk_vuln`). The loader only edits your configuration file and performs no network activity.

Note: the demo script and the offline sample feed are intentionally excluded from packaged releases (see `MANIFEST.in`) and therefore won't be installed via `pip` or `uv tool install`. To run the demo, clone the repository and run `scripts/demo_offline_snyk.sh` locally.
