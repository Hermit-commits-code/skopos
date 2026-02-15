# 🛡️ Spectr

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

## 🛠️ Security Heuristics

Spectr uses a tiered defense-in-depth model:

1. Typosquatting Engine: Detects look-alike packages targeting popular libraries.
2. Structural Analysis: Identifies "Skeleton" packages (sdist < 2KB) used for staging exploits.
3. Identity Verification: Flags brand-jacking (e.g., official prefixes maintained by generic emails).
4. Behavioral Velocity: Monitors release bursts that indicate automated spamming or bot-driven reputation inflation.

## ⚙️ Administration

Command Description

| Command     | Outcome                                           |
| ----------- | ------------------------------------------------- |
| spectr-init | Injects security aliases into .bashrc / .zshrc.   |
| spectr-off  | Emergency bypass: removes all shell interceptions |
| spectr sign | Re-authorizes a manually edited whitelist.        |
| spectr sign | Re-authorizes a manually edited whitelist.        |

## 🛡️ Integrity

Spectr maintains a signed whitelist at ~/.spectr-whitelist. Unauthorized manual modifications trigger an integrity alert, preventing malware from self-whitelisting.
