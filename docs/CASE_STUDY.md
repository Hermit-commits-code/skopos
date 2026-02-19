# THREAT MODEL: Behavioral Analysis of "Social Proof" Attacks

## 🛡️ Executive Summary

This document outlines the **Social Proof Deception** model—a high-frequency attack pattern on package registries. **Skopos** is designed to neutralize this threat by replacing "Visual Trust" (downloads/stars) with **Behavioral Heuristics**.

---

## ☣️ The Threat Model: Inflated Trust

The "Inflated Trust" model exploits the human tendency to trust large numbers. Attackers manipulate metadata to bypass the "gut check" a developer performs before running `pip install`.

### Observed Attack Patterns

1. **Metadata Spoofing**: Using botnets to generate tens of thousands of "downloads" within hours of release.
2. **Version Spraying**: Automating dozens of releases (`0.0.1` through `0.0.25`) to simulate maturity.
3. **The Trap**: A developer sees `50k downloads` and `v0.25.0` and assumes the package is community-vetted.

---

## 🛡️ Skopos Heuristic Defense Layer

Skopos treats all new packages as "untrusted" regardless of popularity metrics.

### Heuristic 1: The Zero-Trust Window

Skopos enforces a **72-hour vetting period**. This is the critical window where security researchers typically identify and report malicious packages.

- **Effect**: Negates the "speed" advantage of a new supply-chain attack.

### Heuristic 2: The Popularity Anomaly Check

Skopos calculates the ratio of **Downloads vs. Age**.

- **The Math**: If $Downloads > 10,000$ and $Age < 7 \text{ days}$, the package is flagged as a high-probability bot-inflation target.

### Heuristic 3: Giant's Immunity (v0.22)

To reduce false positives, Skopos applies "Seniority Heuristics." If a project has **>50 releases** or a massive historical age, metadata gaps (like missing emails) are de-prioritized.

- **Effect**: Stops flagging critical infrastructure like `requests` or `numpy`.

### Heuristic 4: Execution Sandboxing

Suspicious metadata (description strings or setup scripts) is passed through a **RestrictedPython** sandbox to check for unauthorized `os` or `sys` calls before the developer even downloads the wheel.

---

## 🏁 Conclusion

By using **Skopos**, developers move from **Passive Trust** (believing numbers) to **Active Verification** (analyzing behavior). This shift is essential for defending modern Python environments against sophisticated supply-chain deception.

- **Effect**: Stops flagging critical infrastructure like `requests` or `numpy`.

### Heuristic 4: Execution Sandboxing

Suspicious metadata (description strings or setup scripts) is passed through a **RestrictedPython** sandbox to check for unauthorized `os` or `sys` calls before the developer even downloads the wheel.

---

## 🏁 Conclusion

By using **Skopos**, developers move from **Passive Trust** (believing numbers) to **Active Verification** (analyzing behavior). This shift is essential for defending modern Python environments against sophisticated supply-chain deception.
