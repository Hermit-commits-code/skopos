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


def levenshtein_distance(s1, s2):
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


def check_for_typosquatting(package_name):
    """Detects if a package is a 'look-alike' of popular libraries."""
    # High-value targets often impersonated
    targets = [
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "boto3",
        "cryptography",
        "tensorflow",
        "pytorch",
    ]

    name = package_name.lower()
    for target in targets:
        if name == target:
            return False  # Exact match is fine

        distance = levenshtein_distance(name, target)
        # If the name is 1-2 characters off, it's highly suspicious
        if 0 < distance <= 2:
            print(
                f"🚨 TYPOSQUAT ALERT: '{name}' is very similar to the official '{target}' library."
            )
            return True
    return False
