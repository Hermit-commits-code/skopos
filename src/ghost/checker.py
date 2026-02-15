import argparse
import os
import sys

from ghost.similarity import check_for_typosquatting

from .checker_logic import is_package_suspicious  # We'll move logic here.

WHITELIST_FILE = ".ghost-whitelist"


def ensure_whitelist_exists():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write(
                "# Ghost Whitelist - Add trusted package names here (one per line)\n"
            )
        print(f"📦 Created default {WHITELIST_FILE}")


def main():
    ensure_whitelist_exists()
    parser = argparse.ArgumentParser(description="Ghost: Check PyPI package age.")
    parser.add_argument("package", help="The name of the package to check")
    args = parser.parse_args()
    print(f"👻 Ghost is haunting {args.package}...")

    if is_whitelisted(args.package):
        print(f"⚪ {args.package} is whitelisted. Skipping security checks.")
        sys.exit(0)

    if not check_package(args.package):
        sys.exit(1)

    if is_package_suspicious(args.package):
        print(
            f"🚨 ALERT: {args.package} is younger than 72 hours! Possible hallucination."
        )
        sys.exit(1)  # Exit with error code to block further actions
    else:
        print(f"✅ {args.package} appears established.")
        sys.exit(0)


def check_package(package_name: str) -> bool:
    if check_for_typosquatting(package_name):
        print(
            f"Error: Suspected typosquatting for {package_name}. Did you mean a popular package?"
        )
        return False
    return True


def is_whitelisted(package_name):
    try:
        with open(WHITELIST_FILE, "r") as file:
            whitelisted = [line.strip() for line in file.readlines()]
            return package_name in whitelisted
    except FileNotFoundError:
        return False


if __name__ == "__main__":
    main()
