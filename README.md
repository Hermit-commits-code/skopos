# 🛡️ Spectr

![Version](https://img.shields.io/badge/version-0.22.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

Proactive supply-chain defense for the modern Python ecosystem.

forensic analysis of PyPI packages and metadata. It detects typosquatting,
reputation anomalies, account hijackings (resurrection attacks), and
malicious payloads before they ever reach your local environment.

## Table of Contents

- [🛡️ Spectr](#️-spectr)
  - [Table of Contents](#table-of-contents)
  - [🚀 Quick Start](#-quick-start)
    - [🔍 Instant Audit](#-instant-audit)
    - [🛠️ Permanent Protection](#️-permanent-protection)
  - [📦 Installation \& System Footprint](#-installation--system-footprint)
  - [🧠 Forensic Capabilities (v0.22)](#-forensic-capabilities-v022)
  - [🛠️ Usage \& Administration](#️-usage--administration)
  - [🛡️ Trust \& Whitelisting](#️-trust--whitelisting)
  - [📂 Project Structure](#-project-structure)
  - [📊 Feature Comparison](#-feature-comparison)
  - [🗺️ Roadmap \& Future Ideas](#️-roadmap--future-ideas)
    - [v0.23: The Intelligence Layer](#v023-the-intelligence-layer)
    - [v1.0: Enterprise Governance](#v10-enterprise-governance)
  - [⚖️ License](#️-license)

---

## 🚀 Quick Start

### 🔍 Instant Audit

Analyze a package instantly using `uvx`:

```bash
uvx spectr check <package_name>
```

### 🛠️ Permanent Protection

Install Spectr and enable shell hooks to automatically intercept `uv` and
`pip` commands:

```bash
pip install spectr
spectr --install-hook
```

Once installed, running `uv add <package>` (or other wrapped commands) will
trigger a Spectr audit. If a package is flagged, the installation is blocked
until you manually authorize it.

## 📦 Installation & System Footprint

Spectr maintains a minimal and predictable footprint on the host system.

1. Software installation

   Installed via `pip` (or `uv`) into your environment's site-packages:

   ```text
   Path: .venv/lib/python3.x/site-packages/spectr/
   ```

2. Local configuration & data

   Spectr stores state and persistent data under the user's home directory:
   - `Directory: ~/.spectr/`
   - `audit_cache.db`: a local SQLite database storing forensic scores for
     24 hours to optimize performance.
   - `~/.spectr-whitelist`: a list of authorized packages.
   - `~/.spectr-whitelist.sig`: a SHA-256 signature file ensuring whitelist
     integrity against unauthorized tampering.

3. Shell interception

   Running `spectr --install-hook` appends a lightweight wrapper to your shell
   profile (`~/.zshrc` or `~/.bashrc`). The wrapper invokes Spectr to verify
   package safety before allowing `uv add` / `pip install` to proceed.

## 🧠 Forensic Capabilities (v0.22)

Spectr uses a weighted 0–100 Security Score to evaluate risk and includes:

- **Typosquatting Detection** — Uses Levenshtein distance to catch look-alike
  packages (e.g., `reqests` vs `requests`).
- **Giant's Immunity** — Recognizes high-reputation projects (e.g., pandas,
  numpy) to reduce false positives for established infrastructure.
- **Resurrection Tracking** — Flags dormant accounts that suddenly push
  updates after years of inactivity (possible account hijacking).
- **Bot-Inflation Protection** — Detects "social proof" attacks where
  download counts are artificially inflated on new packages.
- **Sandboxed Execution** — Safely evaluates metadata and script snippets in
  a restricted environment.

## 🛠️ Usage & Administration

Common commands:

```bash
spectr audit              # Scan the current project's pyproject.toml
spectr check <package>    # Perform a deep forensic scan on a specific package
spectr --install-hook     # Inject security wrappers into ~/.bashrc or ~/.zshrc
spectr --disable          # Remove shell interceptions and restore defaults
spectr -r --max-depth 2   # Perform a recursive audit of a dependency tree
```

## 🛡️ Trust & Whitelisting

Spectr maintains a cryptographically signed whitelist at `~/.spectr-whitelist`.

- If a package is flagged during an audit, you can choose to trust it locally
  by adding it to the whitelist.
- The whitelist is signed using a SHA-256 hash to prevent unauthorized
  tampering.

## 📂 Project Structure

For developers and auditors, the codebase follows a consolidated, modular
architecture:

```text
spectr/
├── pyproject.toml         # Project metadata and entry points
├── src/
│   └── spectr/            # Source root
│       ├── __init__.py
│       ├── checker.py     # Main CLI & whitelist management
│       ├── checker_logic.py # Forensic heuristics & scoring
│       ├── cache.py       # SQLite cache manager
│       └── sandbox.py     # Restricted execution environment
└── CASE_STUDY.md          # Technical deep-dive on threat models
```

(See attachments for additional documentation and the CASE_STUDY.)

## 📊 Feature Comparison

| Feature         |  Standard Package Managers |              Spectr (v0.22.0) |
| --------------- | -------------------------: | ----------------------------: |
| Primary Goal    |  Installation & Resolution |          Supply-Chain Defense |
| Trust Model     | Implicit (Trusts Registry) |        Zero-Trust (Heuristic) |
| Deep Scan       |                         No | Recursive Dependency Auditing |
| False Positives |    High (on metadata gaps) |        Low (Giant's Immunity) |
| Interception    |                       None |         Real-time Shell Hooks |

## 🗺️ Roadmap & Future Ideas

Spectr is evolving from a local utility into a comprehensive security framework.

### v0.23: The Intelligence Layer

- **Shared Threat Intelligence**: Optional opt-in to report malicious package hashes to a centralized community database.
- **Enhanced Sandboxing**: Moving beyond `RestrictedPython` to lightweight WASM-based execution for deeper script analysis.

### v1.0: Enterprise Governance

- **GitOps Policy Sync**: Ability to fetch signed whitelists from a central repository for team-wide security parity.
- **CI/CD Gating**: Dedicated GitHub Actions and GitLab CI components to block builds containing low-score dependencies.
- **Detailed Forensic Exports**: Support for SARIF and JSON reporting for integration into SOC/SIEM platforms.- **Detailed Forensic Exports**: Support for SARIF and JSON reporting for integration into SOC/SIEM platforms.

## ⚖️ License

Distributed under the MIT License. See the `LICENSE` file for details.

Maintained by Joseph Chu — Spectr GitHub
