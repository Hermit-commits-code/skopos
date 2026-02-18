import math
import re
from collections import Counter
from datetime import datetime, timezone
from skopos.config import load_config

# Load configuration (user overrides default via ~/.skopos/config.toml)
_CFG = load_config()

# --- SCORING CONFIGURATION ---
# Read weights from config with a sane default fallback
SCORING_WEIGHTS = _CFG.get("scoring_weights", {
    "typosquatting": 100,  # Critical: Immediate 0 score
    "payload_risk": 50,  # High: Suspicious binaries/scripts
    "resurrection": 40,  # Medium/High: Potential hijacked account
    "obfuscation": 30,  # Medium: High-entropy filenames/code
    "new_account": 20,  # Low/Medium: Lack of history
    "hidden_identity": 10,  # Low: Missing author contact
    "low_velocity": 10,  # Low: Stale package
})

# --- FORENSIC ENGINES ---


def calculate_entropy(data: str) -> float:
    """Calculates Shannon Entropy to detect obfuscation or packed payloads."""
    if not data:
        return 0.0
    occurrences = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in occurrences.values()
    )


def levenshtein_distance(s1: str, s2: str) -> int:
    """Iterative Levenshtein distance for typosquatting detection."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# --- HEURISTICS ---

def check_for_typosquatting(package_name: str, custom_targets=None):
    """Detects similarity AND keyword-stuffing attacks.

    Uses targets and tuning parameters from the configuration loader by
    default. Callers may pass `custom_targets` to override for a single run.
    """
    cfg = _CFG
    targets = custom_targets or cfg.get("targets", {})
    keyword_extra = cfg.get("keyword_extra_chars", 8)
    name = package_name.lower()

    for target, threshold in targets.items():
        if name == target:
            continue

        # 1. Levenshtein check (Similarity)
        if levenshtein_distance(name, target) <= threshold:
            return True, target

        # 2. Keyword-stuffing check (e.g., 'requests-ultra', 'pip-security')
        # If a high-value brand is in the name but it's not the actual package
        if target in name and (len(name) - len(target)) <= keyword_extra:
            return True, f"{target} (Keyword match)"

    return False, None


def check_resurrection(data: dict):
    """v0.22: Detects dormant account activity with Giant's Immunity."""
    releases = data.get("releases", {})
    if len(releases) < 2:
        return True, {"dormancy": 0, "status": "New"}

    # Giant's Immunity: Established projects are exempt from dormancy flags
    if len(releases) > 50:
        return True, {"releases": len(releases), "status": "Immune (Giant)"}

    upload_times = sorted(
        [
            datetime.fromisoformat(f["upload_time"].replace("Z", ""))
            for r in releases.values()
            for f in r
        ]
    )

    gaps = [
        (upload_times[i] - upload_times[i - 1]).days
        for i in range(1, len(upload_times))
    ]
    max_gap = max(gaps) if gaps else 0
    last_age = (datetime.now(timezone.utc).replace(tzinfo=None) - upload_times[-1]).days

    # Flag if dormant > 2 years then sudden update
    if max_gap > 730 and last_age < 14:
        return False, {"max_gap": max_gap, "last_release": last_age}
    return True, {"max_gap": max_gap}


def check_author_reputation(package_name: str, data: dict):
    """
    v0.22.1: Analyzes author metadata. 
    Cross-references package names against email domains to detect brand-jacking.
    """
    info = data.get("info", {}) or {}
    releases = data.get("releases", {})
    author = (info.get("author") or "").strip()
    email = (info.get("author_email") or "").strip()

    # 1. Giant's Immunity: Established projects are exempt from metadata-gap flagging
    if len(releases) > 30:
        return True, {
            "author": author or "Project Lead", 
            "email": email, 
            "status": "Immune (Giant)"
        }

    # 2. Basic Validation: We must at least have an email to track identity
    if not email:
        return False, {
            "reason": "Missing author email contact", 
            "author": author, 
            "email": "None"
        }

    # 3. Brand-jacking Detection:
    # If the package name claims to be from a major brand, the email must match.
    target_brands = ["google", "microsoft", "amazon", "apple", "adobe", "openai"]
    pkg_lower = package_name.lower()
    email_lower = email.lower()
    
    for brand in target_brands:
        if brand in pkg_lower:
            # If 'google' is in the name, but the email isn't @google.com
            if not email_lower.endswith(f"@{brand}.com"):
                return False, {
                    "reason": f"Suspected {brand.capitalize()} brand-jacking", 
                    "email": email
                }

    return True, {"author": author, "email": email}

def check_reputation(package_name: str, data: dict):
    """v0.22: Detects bot-driven download inflation."""
    info = data.get("info", {}) or {}
    downloads = info.get("downloads", {}).get("last_month", 0)
    releases = data.get("releases", {})

    upload_times = [
        datetime.fromisoformat(f["upload_time"].replace("Z", ""))
        for r in releases.values()
        for f in r
        if r
    ]
    if not upload_times:
        return True, {"downloads": downloads, "age": 0}

    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - min(upload_times)
    ).days or 1

    # High downloads + Very young = Suspected Bot Inflation
    if downloads > 10000 and days_old <= 7:
        return False, {"downloads": downloads, "days_old": days_old}
    return True, {"downloads": downloads, "days_old": days_old}


def scan_payload(package_name: str, data: dict):
    """v0.22: Scans manifest for dangerous file types and obfuscated names."""
    info = data.get("info", {})
    version = info.get("version")
    releases = data.get("releases", {}).get(version, [])

    suspicious = [
        r.get("filename")
        for r in releases
        if any(
            ext in r.get("filename", "").lower()
            for ext in [".exe", ".msi", ".sh", ".bat", ".bin"]
        )
    ]
    entropy = [
        r.get("filename")
        for r in releases
        if calculate_entropy(r.get("filename", "")) > 5.0
    ]

    passed = not (suspicious or entropy)
    return passed, {
        "suspicious": suspicious or "none",
        "high_entropy": entropy or "none",
    }


# --- UTILITIES ---


def get_dependencies(pypi_data: dict) -> list:
    """Extracts a clean list of unique dependency names."""
    requires = pypi_data.get("info", {}).get("requires_dist") or []
    clean_deps = []
    for req in requires:
        if ";" in req and "extra ==" in req:
            continue
        match = re.match(r"^([a-zA-Z0-9\-\._]+)", req)
        if match:
            clean_deps.append(match.group(1).lower())
    return list(set(clean_deps))


def calculate_skopos_score(results: dict) -> int:
    """v0.22: Aggregates heuristics into a final safety score (0-100)."""
    score = 100

    # Critical override
    if results.get("Typosquatting", (False,))[0]:
        return 0

    mapping = {
        "Resurrection": "resurrection",
        "Payload": "payload_risk",
        "Reputation": "new_account",
        "Identity": "hidden_identity",
        "Sandbox": "sandbox_violation",
        "Obfuscation": "obfuscation",
    }

    for key, weight_key in mapping.items():
        passed, _ = results.get(key, (True, {}))
        if not passed:
            score -= SCORING_WEIGHTS.get(weight_key, 0)

    return max(0, min(100, score))


def disable_hooks():
    """v0.11.0: Removes Skopos interception logic from shell RC files."""
    import os

    rc_file = os.path.expanduser(
        "~/.zshrc" if "zsh" in os.environ.get("SHELL", "") else "~/.bashrc"
    )
    if not os.path.exists(rc_file):
        return
    try:
        with open(rc_file, "r") as f:
            lines = [l for l in f.readlines() if "Skopos" not in l and "uv()" not in l]
        with open(rc_file, "w") as f:
            f.writelines(lines)
        print(f"🛡️  Hooks removed from {rc_file}.")
    except Exception as e:
        print(f"❌ Error disabling hooks: {e}")

def check_identity(package_name, data):
    """v0.22.1: Alias for author reputation to maintain test compatibility."""
    return check_author_reputation(package_name, data)

def check_for_updates(current_version):
    """v0.22: Checks PyPI to see if a newer version of Skopos exists."""
    url = "https://pypi.org/pypi/skopos/json"
    try:
        import requests
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            latest = response.json().get("info", {}).get("version")
            if latest != current_version:
                # We return False to indicate an update is needed (as per your test logic)
                return False, latest
        return True, current_version
    except Exception:
        # If offline, we pass the check to avoid blocking the user
        return True, current_version