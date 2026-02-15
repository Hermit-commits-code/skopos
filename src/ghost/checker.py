import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone

import requests

from ghost.similarity import check_for_typosquatting

WHITELIST_FILE = os.path.expanduser("~/.ghost-whitelist")


# --- HELPER FUNCTIONS ---
def install_shell_hook():
    """v0.8.0: Automates the creation of the pip-install alias."""
    # Detect shell type
    shell_path = os.environ.get("SHELL", "")
    if "zsh" in shell_path:
        rc_file = os.path.expanduser("~/.zshrc")
    else:
        rc_file = os.path.expanduser("~/.bashrc")

    hook_cmd = (
        "\n# Ghost Security Hook\nalias pip-install='ghost $1 && pip install $1'\n"
    )

    try:
        # Check if already installed to avoid duplicates
        if os.path.exists(rc_file):
            with open(rc_file, "r") as f:
                if "Ghost Security Hook" in f.read():
                    print(f"ℹ️  Hook already exists in {rc_file}")
                    return

        with open(rc_file, "a") as f:
            f.write(hook_cmd)
        print(f"✅ Hook added to {rc_file}. Please run 'source {rc_file}' to activate.")
    except Exception as e:
        print(f"❌ Failed to install hook: {e}")


def print_hook_instruction():
    print("\n🛡️  To fully protect your environment, add this to your .bashrc or .zshrc:")
    print("alias pip-install='ghost check $1 && pip install $1'")


def ensure_whitelist_exists():
    """Ensures the whitelist file exists to prevent FileNotFoundError."""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write(
                "# Ghost Whitelist - Add trusted package names here (one per line)\n"
            )
        print(f"📦 Created default {WHITELIST_FILE}")


def is_whitelisted(package_name):
    """Checks if a package is in the local trust list."""
    if not os.path.exists(WHITELIST_FILE):
        return False
    with open(WHITELIST_FILE, "r") as file:
        # Strip whitespace and ignore comments
        whitelisted = [
            line.strip() for line in file.readlines() if not line.startswith("#")
        ]
        return package_name in whitelisted


def fetch_pypi_data(package_name):
    """Single entry point for PyPI data to avoid redundant API calls."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        headers = {
            "User-Agent": "Ghost-Security-Tool/0.7.0 (https://github.com/Hermit-commits-code/dependency-ghost)",
            "Accept": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=5, verify=True)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None


# --- SECURITY ENGINES ---
def verify_whitelist_integrity():
    if not os.path.exists(WHITELIST_FILE):
        return True

    with open(WHITELIST_FILE, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()

    sig_file = WHITELIST_FILE + ".sig"
    if not os.path.exists(sig_file):
        # First time setup: create the signature
        with open(sig_file, "w") as f:
            f.write(current_hash)
        return True

    with open(sig_file, "r") as f:
        stored_hash = f.read().strip()

    if current_hash != stored_hash:
        print(
            "🚨 SECURITY BREACH: The whitelist has been modified by an external process!"
        )
        print("Please verify ~/.ghost-whitelist and run 'ghost sign' to re-authorize.")
        return False
    return True


def check_velocity(data):
    """v0.6.0: Checks if a package is pushing too many versions too fast (Bot behavior)."""
    releases = data.get("releases", {})
    if not releases:
        return True

    upload_times = []
    for version in releases:
        for file_info in releases[version]:
            upload_times.append(
                datetime.fromisoformat(file_info["upload_time"].replace("Z", ""))
            )

    if not upload_times:
        return True

    first_upload = min(upload_times)
    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - first_upload
    ).days or 1

    # Flag if > 15 releases in less than 3 days (Classic spray-and-pray attack)
    if days_old < 3 and len(releases) > 15:
        print(
            f"⚠️  CAUTION: Unusual release velocity ({len(releases)} versions in {days_old} days)."
        )
        return False
    return True


def check_reputation(package_name, data):
    """v0.6.0: Flags 'Too good to be true' scenarios (50k downloads on a 1-day old package)."""
    info = data.get("info", {})
    # Note: PyPI stats are often 0 in JSON, but we check if provided
    downloads = info.get("downloads", {}).get("last_month", 0)

    releases = data.get("releases", {})
    upload_times = [
        datetime.fromisoformat(r[0].get("upload_time").replace("Z", ""))
        for r in releases.values()
        if r
    ]

    if not upload_times:
        return True

    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - min(upload_times)
    ).days or 1
    # High downloads + Very young = Suspected Bot Inflation
    if downloads > 10000 and days_old < 3:
        print(
            f"🚩 WARNING: {package_name} has high download counts but is only {days_old} days old!"
        )
        return False
    return True


def check_identity(package_name, data):
    """v0.9.0: Detects if a 'branded' package is maintained by a generic email domain."""
    info = data.get("info", {})
    email = info.get("author_email") or info.get("maintainer_email") or ""
    email = email.lower()
    name = package_name.lower()

    # High-target prefixes and generic domains
    brands = ["google", "aws", "azure", "microsoft", "facebook", "meta", "apple"]
    generic_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "protonmail.com",
    ]

    for brand in brands:
        if name.startswith(brand):
            # If it matches a brand but uses a generic email, flag it
            if any(domain in email for domain in generic_domains):
                print(
                    f"🚨 IDENTITY MISMATCH: '{brand}' package is maintained by a generic email ({email})!"
                )
                return False
    return True


def is_package_suspicious(data):
    """v0.3.0: Basic Age Check (The 72-hour rule)."""
    releases = data.get("releases", {})
    if not releases:
        return True

    upload_times = [
        datetime.fromisoformat(r[0].get("upload_time").replace("Z", ""))
        for r in releases.values()
        if r
    ]

    first_upload = min(upload_times)
    hours_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - first_upload
    ).total_seconds() / 3600

    if hours_old < 72:
        return True
    return False


def sign_whitelist():
    with open(WHITELIST_FILE, "rb") as f:
        new_hash = hashlib.sha256(f.read()).hexdigest()
    with open(WHITELIST_FILE + ".sig", "w") as f:
        f.write(new_hash)
    print("🖋️  Whitelist signature updated successfully.")


# --- MAIN EXECUTION ---


def main():
    ensure_whitelist_exists()

    parser = argparse.ArgumentParser(description="Ghost: Supply Chain Defense Tool")
    parser.add_argument("package", help="The name of the package to check")
    parser.add_argument(
        "--sign", action="store_true", help="Sign the whitelist after manual changes"
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install the pip-install shell alias",
    )
    args = parser.parse_args()

    print(f"👻 Ghost is haunting {args.package}...")

    if args.install_hook:
        install_shell_hook()
        sys.exit(0)

    if args.sign:
        sign_whitelist()
        sys.exit(0)

    if not verify_whitelist_integrity():
        sys.exit(1)

    # 1. Check Whitelist First (Express Lane)
    if is_whitelisted(args.package):
        print(f"⚪ {args.package} is whitelisted. Skipping security checks.")
        sys.exit(0)

    # 2. Typosquatting Check (Local Logic)
    if check_for_typosquatting(args.package):
        print(f"🚨 ALERT: Suspected typosquatting for '{args.package}'.")
        sys.exit(1)

    # 3. Fetch Remote Data Once
    data = fetch_pypi_data(args.package)
    if not data:
        print(f"❓ Could not find {args.package} on PyPI. Proceed with caution.")
        sys.exit(0)

    # 4. Age Check
    if is_package_suspicious(data):
        print(f"🚨 ALERT: {args.package} is younger than 72 hours!")
        sys.exit(1)

    # 5. Reputation & Velocity Checks (v0.6.0)
    if (
        not check_reputation(args.package, data)
        or not check_velocity(data)
        or not check_reputation(args.package, data)
        or not check_velocity(data)
    ):
        print("🛑 SECURITY RISK: Metadata suggests automated trust inflation.")
        sys.exit(1)

    print(f"✅ {args.package} appears established and safe.")
    sys.exit(0)


if __name__ == "__main__":
    main()
