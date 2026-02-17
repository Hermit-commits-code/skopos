import math
import re
from collections import Counter
from datetime import datetime, timezone

import requests

SCORING_WEIGHTS = {
    "typosquatting": 100,  # Critical: Immediate 0 score
    "resurrection": 40,  # High: Potential hijacking
    "payload_risk": 50,  # High: Script/Binary found in manifest
    "obfuscation": 30,  # Medium:
    "sandbox_violation": 60,
    "new_account": 30,  # Medium: Lack of history
    "hidden_identity": 10,  # Low: Lack of transparency
    "low_velocity": 10,  # Low: Stale package
}


def is_package_suspicious(package_name: str, age_threshold_hours: int = 72) -> bool:
    """
    Check if a PyPI package is younger than the specified age threshold.

    Args:
        package_name (str): The name of the package to check.
        age_threshold_hours (int): The age threshold in hours (default is 72).

    Returns:
        bool: True if the package is suspicious (younger than threshold), False otherwise.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            # Not found on PyPI = impossible to install, so not 'suspicious' yet
            return False

        data = response.json()

        # Get the first release's upload time
        releases = data.get("releases", {})
        if not releases:
            return False

        first_version = list(releases.keys())[0]
        upload_time_str = releases[first_version][0]["upload_time"]

        upload_time = datetime.fromisoformat(upload_time_str).replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)

        age_in_hours = (now - upload_time).total_seconds() / 3600

        return age_in_hours < age_threshold_hours

    except Exception:
        return False


def disable_hooks():
    """v0.11.0: Removes Spectr aliases from shell configuration files."""
    import os

    shell_path = os.environ.get("SHELL", "")
    rc_file = os.path.expanduser("~/.zshrc" if "zsh" in shell_path else "~/.bashrc")

    if not os.path.exists(rc_file):
        print(f"❌ Configuration file {rc_file} not found.")
        return

    try:
        with open(rc_file, "r") as f:
            lines = f.readlines()

        # Filter out any lines related to Spectr
        new_lines = [
            line
            for line in lines
            if "Spectr" not in line
            and "pip-install" not in line
            and "uv-add" not in line
        ]

        if len(lines) == len(new_lines):
            print("ℹ️  No Spectr hooks found to disable.")
        else:
            with open(rc_file, "w") as f:
                f.writelines(new_lines)
            print(
                f"🛡️  Spectr hooks removed from {rc_file}. Restart your terminal to apply changes."
            )
    except Exception as e:
        print(f"❌ Failed to disable hooks: {e}")


def check_for_typosquatting(package_name):
    """
    v0.12.0: Checks if package_name is a typosquatting attempt.
    Returns: (bool, str or None) -> (is_malicious, target_name)
    """
    # High-value targets to protect
    SQUAT_TARGETS = {
        # Core Infrastructure
        "requests": 1,
        "urllib3": 1,
        "pip": 1,
        "setuptools": 1,
        # Cloud & DevOps
        "boto3": 1,
        "botocore": 1,
        "ansible": 1,
        "docker": 1,
        "pulumi": 1,
        # Data Science & AI
        "pandas": 1,
        "numpy": 1,
        "scipy": 1,
        "matplotlib": 1,
        "tensorflow": 2,
        "torch": 1,
        "scikit-learn": 2,
        "openai": 1,
        # Web Frameworks
        "django": 1,
        "flask": 1,
        "fastapi": 1,
        "pydantic": 1,
        # Security
        "cryptography": 2,
        "pyjwt": 1,
        "passlib": 1,
    }

    name = package_name.lower()

    for target, threshold in SQUAT_TARGETS.items():
        # Skip if it's an exact match (that's the real package)
        if name == target:
            continue

        # Simple Levenshtein implementation (or use Levenshtein library if installed)
        distance = levenshtein_distance(name, target)

        if distance <= threshold:
            print(f"🚨 ALERT: Suspected typosquatting for '{name}'.")
            print(f"   It is remarkably similar to the popular package '{target}'.")
            return True, target

    return False, None


def levenshtein_distance(s1, s2):
    """Simple iterative Levenshtein distance calculation."""
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


def parse_requirement_name(req_string):
    """
    Extracts just the package name from a dependency string.
    Example: 'requests (>=2.28.0) ; extra == "security"' -> 'requests'
    """
    if not req_string:
        return None
    # Match the first sequence of alphanumeric characters/hyphens/underscores
    match = re.match(r"^([a-zA-Z0-9\-\._]+)", req_string)
    return match.group(1) if match else None


def get_dependencies(pypi_data):
    """
    Extracts a list of clean dependency names from PyPI metadata.
    """
    info = pypi_data.get("info", {})
    requires = info.get("requires_dist") or []

    clean_deps = []
    for req in requires:
        # Filter out 'extras' like [docs], [test] to avoid bloat
        if ";" in req and "extra ==" in req:
            continue

        name = parse_requirement_name(req)
        if name:
            clean_deps.append(name.lower())

    return list(set(clean_deps))  # Return unique names


def check_resurrection(data):
    """v0.18.1: Detects account resurrection with 'Giant's Immunity'."""
    releases = data.get("releases", {})
    if len(releases) < 2:
        return True, {"max_dormancy_days": 0, "recent_activity": True}

    upload_times = []
    for pkg_version in releases:
        for file_info in releases[pkg_version]:
            upload_times.append(
                datetime.fromisoformat(file_info["upload_time"].replace("Z", ""))
            )

    upload_times.sort()

    # Calculate gaps between consecutive releases
    gaps = [
        (upload_times[i] - upload_times[i - 1]).days
        for i in range(1, len(upload_times))
    ]
    max_gap = max(gaps) if gaps else 0

    # Check if the most recent release was very recent (last 14 days)
    last_release_age = (
        datetime.now(timezone.utc).replace(tzinfo=None) - upload_times[-1]
    ).days
    is_recent = last_release_age < 14

    meta = {"max_dormancy_days": max_gap, "recent_activity": is_recent}

    # LOGIC: Flag only if there's a huge gap followed by a sudden burst,
    # BUT give immunity to established "Giants" (more than 30 releases).
    if max_gap > 730 and is_recent and len(releases) < 30:
        return False, meta

    return True, meta


def scan_payload(package_name, data):
    info = data.get("info", {})
    version = info.get("version")
    releases = data.get("releases", {}).get(version, [])

    suspicious_files = []
    entropy_flags = []

    for r in releases:
        filename = r.get("filename", "").lower()
        # Extension check
        if any(ext in filename for ext in [".exe", ".msi", ".sh", ".bat", ".bin"]):
            suspicious_files.append(filename)

        # Entropy check on filename (as a proxy for obfuscated names)
        if calculate_entropy(filename) > 5.0:
            entropy_flags.append(filename)  # Track the specific files

    passed = len(suspicious_files) == 0 and len(entropy_flags) == 0
    meta = {
        "suspicious_extensions": suspicious_files if suspicious_files else "none",
        "high_entropy_files": entropy_flags if entropy_flags else "none",
    }
    return passed, meta


def calculate_spectr_score(results):
    """v0.20.0: Aggregates advanced heuristics into a 0-100 risk score."""
    score = 100

    # 1. Critical: Typosquatting (Manual override to 0)
    if results.get("typosquatting", (False,))[0]:
        return 0

    # 2. Heuristic Penalties mapping
    # Note: 'Identity' and 'Obfuscation' are now part of this unified mapping
    penalties = {
        "Resurrection": "resurrection",
        "Payload": "payload_risk",
        "Velocity": "low_velocity",
        "Reputation": "new_account",
        "Identity": "hidden_identity",
        "Obfuscation": "obfuscation",
    }

    for res_key, weight_key in penalties.items():
        # Default to (True, {}) if a check is missing from the results
        passed, _ = results.get(res_key, (True, {}))

        if not passed:
            score -= SCORING_WEIGHTS.get(weight_key, 0)

    # Ensure the score stays within bounds [0, 100]
    return max(0, min(100, score))


def calculate_entropy(data):
    """v0.20.0: Calculates Shannon Entropy to detect obfuscation."""
    if not data:
        return 0
    occurances = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in occurances.values()
    )


def check_author_reputation(data):
    """v0.20.0: Analyzes author metadata for risk patterns."""
    info = data.get("info", {}) or {}
    author_raw = info.get("author")
    author = author_raw.strip() if author_raw else ""
    email = info.get("author_email", "").strip()

    # Flag missing contact info - a classic 'hidden identity' trait
    if not author or not email:
        return False, {"reason": "Missing author or email"}

    return True, {"author": author, "email": email}
