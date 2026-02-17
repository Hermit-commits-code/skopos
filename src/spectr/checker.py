import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone

import requests
from packaging import version
from rich.console import Console
from rich.table import Table

from spectr.cache import CacheManager
from spectr.checker_logic import (
    calculate_spectr_score,
    check_author_reputation,
    check_for_typosquatting,
    check_resurrection,
    disable_hooks,
    scan_payload,
)
from spectr.sandbox import execute_in_sandbox

cache = CacheManager()

VERSION = "0.21.0"
console = Console()
WHITELIST_FILE = os.path.expanduser("~/.spectr-whitelist")


# --- HELPER FUNCTIONS ---
def install_shell_hook():
    # Detect shell type
    shell_path = os.environ.get("SHELL", "")
    if "zsh" in shell_path:
        rc_file = os.path.expanduser("~/.zshrc")
    else:
        rc_file = os.path.expanduser("~/.bashrc")

    hook_cmd = (
        "\n# Spectr Security Hooks\n"
        "alias pip-install='spectr $1 && pip install $1'\n"
        "alias uv-add='spectr $1 && uv add $1'\n"
        "alias uv-pip='spectr $1 && uv pip install $1'\n"
    )

    try:
        # Check if already installed to avoid duplicates
        if os.path.exists(rc_file):
            with open(rc_file, "r") as f:
                if "Spectr Security Hook" in f.read():
                    print(f"ℹ️  Hook already exists in {rc_file}")
                    return

        with open(rc_file, "a") as f:
            f.write(hook_cmd)
        print(f"✅ Hook added to {rc_file}. Please run 'source {rc_file}' to activate.")
    except Exception as e:
        print(f"❌ Failed to install hook: {e}")


def print_hook_instruction():
    print("\n🛡️  To fully protect your environment, add this to your .bashrc or .zshrc:")
    print("alias pip-install='Spectr check $1 && pip install $1'")


def ensure_whitelist_exists():
    """Ensures the whitelist file exists to prevent FileNotFoundError."""
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write(
                "# Spectr Whitelist - Add trusted package names here (one per line)\n"
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
            "User-Agent": "Spectr-Security-Tool/0.10.0 (https://github.com/Hermit-commits-code/spectr)",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        response = requests.get(url, headers=headers, timeout=5, verify=True)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.RequestException:
        return None


# --- SECURITY ENGINES ---
def check_structure(data):
    info = data.get("info", {})
    pkg_version = info.get("version")
    releases = data.get("releases", {}).get(pkg_version, [])

    sdist_size = 0
    for release in releases:
        if release.get("packagetype") == "sdist":
            sdist_size = release.get("size", 0)
            break

    meta = {"sdist_size_bytes": sdist_size}

    if 0 < sdist_size < 2048:
        return False, meta
    return True, meta


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
        print(
            "Please verify ~/.spectr-whitelist and run 'spectr sign' to re-authorize."
        )
        return False
    return True


def check_velocity(data):
    releases = data.get("releases", {})
    if not releases:
        return True, {"releases": 0, "days_old": 0}

    upload_times = []
    for pkg_version in releases:
        for file_info in releases[pkg_version]:
            upload_times.append(
                datetime.fromisoformat(file_info["upload_time"].replace("Z", ""))
            )

    if not upload_times:
        return True, {"releases": len(releases), "days_old": 0}

    first_upload = min(upload_times)
    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - first_upload
    ).days or 1

    # Metadata capture
    meta = {"releases": len(releases), "days_old": days_old}

    # Logic: Flag if > 15 releases in less than 3 days
    if days_old < 3 and len(releases) > 15:
        return False, meta

    return True, meta


def check_reputation(package_name, data):
    info = data.get("info", {})
    downloads = info.get("downloads", {}).get("last_month", 0)
    releases = data.get("releases", {})

    upload_times = [
        datetime.fromisoformat(r[0].get("upload_time").replace("Z", ""))
        for r in releases.values()
        if r
    ]

    if not upload_times:
        return True, {"downloads": downloads, "days_old": 0}

    days_old = (
        datetime.now(timezone.utc).replace(tzinfo=None) - min(upload_times)
    ).days or 1
    meta = {"downloads": downloads, "days_old": days_old}

    # High downloads + Very young = Suspected Bot Inflation
    if downloads > 10000 and days_old < 3:
        return False, meta
    return True, meta


def check_identity(package_name, data):
    info = data.get("info", {})
    email = (info.get("author_email") or info.get("maintainer_email") or "").lower()

    meta = {"email": email or "hidden"}
    brands = ["google", "aws", "azure", "microsoft", "facebook", "meta", "apple"]
    generic_domains = [
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "protonmail.com",
    ]

    for brand in brands:
        if package_name.lower().startswith(brand):
            if any(domain in email for domain in generic_domains):
                return False, meta
    return True, meta


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


def check_for_updates(current_version):
    try:
        # We query the PyPI JSON API for Spectr's metadata
        response = requests.get("https://pypi.org/pypi/spectr/json", timeout=1.5)
        if response.status_code == 200:
            latest_version = response.json()["info"]["version"]

            # Use packaging.version to compare correctly (e.g., 0.15.0 > 0.5)
            if version.parse(latest_version) > version.parse(current_version):
                print(
                    f"🔔 NOTICE: A new version of Spectr is available ({latest_version})."
                )
                print("   Run 'uvx --refresh spectr' to update.")
    except Exception:
        # Fail silently: update checks should never block a security tool
        pass


def display_report(package, results, score):
    color = "green" if score > 80 else "yellow" if score >= 50 else "red"
    table = Table(
        title=f"Spectr Forensic Report: [bold blue]{package}[/bold blue]\n"
        f"Risk Score: [bold {color}]{score}/100[/bold {color}]",
        header_style="bold magenta",
    )
    table.add_column("Heuristic", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Forensic Evidence", style="white")

    for check_name, value in results.items():
        if check_name == "score":
            continue

        passed, meta = value  # Safe unpacking
        status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        table.add_row(check_name, status, str(meta))

    console.print("\n")
    console.print(table)


# --- MAIN EXECUTION ---
def main():
    global VERSION
    ensure_whitelist_exists()
    parser = argparse.ArgumentParser(
        description="🛡️  Spectr: Proactive Supply-Chain Defense | Version 0.21.0"
    )

    # Flexible positionals for 'check package' or 'package'
    parser.add_argument("args", nargs="*", help="Command and package name")

    # Flags
    parser.add_argument("--sign", action="store_true", help="Sign the whitelist")
    parser.add_argument("--install-hook", action="store_true", help="Install hooks")
    parser.add_argument("--disable", action="store_true", help="Remove hooks")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show forensic metrics"
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Audit the entire dependency tree",
    )
    parser.add_argument(
        "--max-depth", type=int, default=3, help="Maximum depth of dependency crawling"
    )
    args = parser.parse_args()

    # --- 1. Priority Administrative Actions ---
    if args.disable:
        disable_hooks()
        sys.exit(0)
    if args.install_hook:
        install_shell_hook()
        sys.exit(0)
    if args.sign:
        sign_whitelist()
        sys.exit(0)

    # --- 2. Argument Routing ---
    package = None
    if len(args.args) >= 2 and args.args[0] == "check":
        package = args.args[1]
    elif len(args.args) == 1:
        package = args.args[0]

    if not package:
        parser.print_help()
        sys.exit(0)

    # --- 3. Update Check (Non-blocking, skipped for JSON) ---
    if not args.json:
        check_for_updates(VERSION)

    # --- 4. Security Integrity Check ---
    if not verify_whitelist_integrity():
        print("❌ Integrity error. Run 'spectr --sign' to re-authorize.")
        sys.exit(1)

    if is_whitelisted(package):
        print(f"⚪ {package} is whitelisted. Skipping.")
        sys.exit(0)

    # --- 5. Local Typosquatting ---
    is_squat, target = check_for_typosquatting(package)
    if is_squat:
        sys.exit(1)

    # --- 6. Recursive Forensic Suite ---
    task_queue = [(package, 0)]
    visited = set()
    all_results = {}  # Store results for every package: {name: results_dict}

    with console.status(
        f"[bold green]Auditing {package} and dependencies...", spinner="dots"
    ) as status:
        while task_queue:
            current_pkg, current_depth = task_queue.pop(0)

            if current_pkg in visited or current_depth > args.max_depth:
                continue

            status.update(f"[bold green]Auditing {current_pkg}...")
            data = fetch_pypi_data(current_pkg)

            if not data:
                visited.add(current_pkg)
                continue

            pkg_version = data.get("info", {}).get("version", "0.0.0")
            cached_audit = cache.get_cached_audit(current_pkg, pkg_version)

            if cached_audit:
                pkg_score, pkg_findings = cached_audit
                all_results[current_pkg] = pkg_findings
                # Continue dependency discovery even on cache hit
                if args.recursive and current_depth < args.max_depth:
                    from spectr.checker_logic import get_dependencies

                    sub_deps = get_dependencies(data)
                    for dep in sub_deps:
                        if dep not in visited:
                            task_queue.append((dep, current_depth + 1))
                visited.add(current_pkg)
                continue

            payload_passed, payload_meta = scan_payload(current_pkg, data)

            setup_content = data.get("info", {}).get("description", "")
            sandbox_passed, sandbox_meta = execute_in_sandbox(setup_content)
            safe_data = data if data is not None else {}
            safe_info = safe_data.get("info", {}) or {}
            # Run Forensics
            pkg_findings = {
                "Reputation": check_reputation(current_pkg, safe_data),
                "Velocity": check_velocity(safe_data),
                "Identity": check_author_reputation(
                    safe_data
                ),  # Use the new v0.20.0 logic here
                "Structure": check_structure(safe_data),
                "Resurrection": check_resurrection(safe_data),
                "Payload": (payload_passed, payload_meta),
                "Obfuscation": (
                    payload_meta.get("high_entropy_files") == "none",
                    payload_meta,
                ),
                "Sandbox": (sandbox_passed, sandbox_meta),  # New v0.21.0 heuristic
            }
            # Calculate the score for this specific package
            pkg_score = calculate_spectr_score(pkg_findings)
            pkg_findings["score"] = pkg_score  # Store it in the results
            all_results[current_pkg] = pkg_findings
            cache.save_audit(current_pkg, pkg_version, pkg_score, pkg_findings)
            visited.add(current_pkg)

            # If recursive flag is set, find more friends to audit
            if args.recursive and current_depth < args.max_depth:
                from spectr.checker_logic import get_dependencies

                sub_deps = get_dependencies(data)
                for dep in sub_deps:
                    if dep not in visited:
                        task_queue.append((dep, current_depth + 1))
    all_passed = True
    for pkg_name, pkg_results in all_results.items():
        # Only iterate over findings that are actually tuples (status, meta)
        findings = [v for k, v in pkg_results.items() if k != "score"]
        if not all(status for status, meta in findings):
            all_passed = False
            break
    # --- 8. JSON Export (Primary Machine Output) ---
    if args.json:
        import json

        output = {
            "root_package": package,
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_safety": "safe" if all_passed else "risk",
            "tree_results": {
                name: {
                    "score": res.get("score"),
                    "findings": {
                        h_name: {"passed": val[0], "data": val[1]}
                        for h_name, val in res.items()
                        if h_name != "score"
                    },
                }
                for name, res in all_results.items()
            },
        }
        print(json.dumps(output, indent=2))
        sys.exit(0 if all_passed else 1)

    # --- 9. Reporting (Human-Readable) ---
    # For now, we display the report for the main package requested
    if package in all_results:
        # Extract the score we stored during the audit loop
        pkg_score = all_results[package].get("score", 100)
        display_report(package, all_results[package], pkg_score)

        # If recursive, show a summary of the dependencies
        if args.recursive and len(all_results) > 1:
            console.print("\n[bold]Tree Audit Summary:[/bold]")
            for name, results in all_results.items():
                if name == package:
                    continue  # Skip root, already shown

                res_score = results.get("score", 100)
                color = (
                    "green"
                    if res_score > 80
                    else "yellow"
                    if res_score >= 50
                    else "red"
                )
                status_icon = "[green]✔[/green]" if res_score > 80 else "[red]✘[/red]"
                console.print(
                    f"  {status_icon} {name} ([{color}]{res_score}/100[/{color}])"
                )
    # --- 10. Final Gatekeeper Logic ---
    if not all_passed:
        console.print(
            "\n[bold red]🛑 SECURITY RISK:[/bold red] Forensic anomalies detected in the dependency tree."
        )
        sys.exit(1)

    console.print(
        f"\n[bold green]✅ {package}[/bold green] and its tree appear established and safe."
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
