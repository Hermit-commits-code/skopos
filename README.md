# 🛡️ Spectr

![Version](https://img.shields.io/badge/version-0.13.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Security](https://img.shields.io/badge/forensics-enabled-red)

**Proactive Supply-Chain Defense for the Modern Python Ecosystem.**

Spectr is a high-speed security gatekeeper designed to intercept malicious packages _before_ they reach your local environment. It performs multi-layered forensic analysis on PyPI metadata to detect typosquatting, skeleton packages, and reputation anomalies.

---

## 🚀 Installation & Usage

### Instant Audit (via uvx)

Analyze any package without installing Spectr:

```bash
uvx spectr check <package_name>
```

### Permanent Protection

Install Spectr and inject security hooks into your shell (pip and uv will be automatically audited):

```bash
uv pip install spectr
spectr-init
```

## Advanced Diagnostics (New in v0.12.0)

### Detailed forensic breakdown

```bash
uvx spectr check <package> --verbose
```

### Machine-readable output for CI/CD pipelines

```bash
uvx spectr check <package> --json
```

## 🛠️ Security Heuristics

Spectr uses a tiered defense-in-depth model:

1. Typosquatting Engine: Detects look-alike packages targeting popular libraries.
2. Structural Analysis: Identifies "Skeleton" packages (sdist < 2KB) used for staging exploits.
3. Identity Verification: Flags brand-jacking (e.g., official prefixes maintained by generic emails).
4. Behavioral Velocity: Monitors release bursts that indicate automated spamming or bot-driven reputation inflation.

## ⚙️ Administration

Command Description

| Command       | Outcome                                             |
| ------------- | --------------------------------------------------- |
| spectr-init   | Injects security aliases into .bashrc / .zshrc.     |
| spectr-off    | Emergency bypass: removes all shell interceptions   |
| spectr sign   | Re-authorizes a manually edited whitelist.          |
| spectr --json | Outputs analysis results in structured JSON format. |

## 🛡️ Integrity

Spectr maintains a signed whitelist at ~/.spectr-whitelist. Unauthorized manual modifications trigger an integrity alert, preventing malware from self-whitelisting.

## Why Spectr?

| Feature          | `pip` / `uv`                         | Spectr (v0.16.0+)                         |
| :--------------- | :----------------------------------- | :---------------------------------------- |
| **Primary Goal** | Installation & Dependency Resolution | Supply-Chain Defense & Forensics          |
| **Trust Model**  | Implicit (Trusts PyPI Registry)      | Zero-Trust (Heuristic Verification)       |
| **Deep Scan**    | None (Resolves versions only)        | **Recursive Auditor** (Scans entire tree) |
| **Security**     | Reactive (Scan after install)        | **Proactive** (Scan before download)      |
| **Output**       | Progress Bars                        | Forensic Reports & Dependency Trees       |
