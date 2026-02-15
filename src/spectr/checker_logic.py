import re
from datetime import datetime, timezone

import requests


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
