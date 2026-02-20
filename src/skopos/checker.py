import argparse
import hashlib
import os
import sys
from pathlib import Path

import requests
import tomllib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skopos.cache import CacheManager
from skopos.checker_logic import (
    calculate_skopos_score,
    check_author_reputation,
    check_for_typosquatting,
    check_reputation,
    check_resurrection,
    disable_hooks,
    scan_payload,
    check_for_updates,
    check_identity
)
from skopos.integrations.snyk_adapter import SnykAdapter
from skopos.integrations.socket_adapter import SocketAdapter
import re

# --- CONFIGURATION ---
VERSION = "0.22.0"
console = Console()
cache = CacheManager()
WHITELIST_FILE = os.path.expanduser("~/.skopos-whitelist")
SIG_FILE = WHITELIST_FILE + ".sig"

# --- WHITELIST & INTEGRITY ---


def ensure_whitelist_exists():
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w") as f:
            f.write("# Skopos Whitelist - Trusted packages\n")
        sign_whitelist()


def is_whitelisted(package_name):
    if not os.path.exists(WHITELIST_FILE):
        return False
    with open(WHITELIST_FILE, "r") as f:
        return package_name in [l.strip() for l in f if not l.startswith("#")]


def add_to_whitelist(package_name):
    if is_whitelisted(package_name):
        return
    with open(WHITELIST_FILE, "a") as f:
        f.write(f"{package_name}\n")
    console.print(f"✅ [green]{package_name}[/green] added to whitelist.")


def sign_whitelist():
    with open(WHITELIST_FILE, "rb") as f:
        new_hash = hashlib.sha256(f.read()).hexdigest()
    with open(SIG_FILE, "w") as f:
        f.write(new_hash)
    console.print("🖋️  [dim]Whitelist signature updated.[/dim]")


def verify_whitelist_integrity():
    if not os.path.exists(WHITELIST_FILE):
        return True
    if not os.path.exists(SIG_FILE):
        return False
    with open(WHITELIST_FILE, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    with open(SIG_FILE, "r") as f:
        return current_hash == f.read().strip()


def check_velocity(pypi_data: dict):
    """Compatibility wrapper used by older tests to check project velocity.

    Returns (status, meta) where meta includes the number of releases.
    """
    # Simple velocity heuristic: many releases in a short span is suspicious
    releases = pypi_data.get("releases", {})
    num_releases = len(releases)

    # If the project has an unusually high number of rapid releases, flag it
    if num_releases >= 20:
        return False, {"releases": num_releases}

    # Otherwise fall back to the resurrection logic for more nuanced checks
    status, meta = check_resurrection(pypi_data)
    meta_out = dict(meta) if isinstance(meta, dict) else {"info": meta}
    meta_out["releases"] = num_releases
    return status, meta_out


# --- FORENSIC ENGINE ---


def fetch_pypi_data(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=5)
        return response.json() if response.status_code == 200 else None
    except Exception:
        return None


def check_package(package, args, depth=0):
    if is_whitelisted(package):
        console.print(
            f"✅ [bold green]{package}[/bold green] is in your trusted whitelist. Skipping forensic audit."
        )
        return True, 100

    cached = cache.get_cached_audit(package, "latest")
    if cached:
        score, _ = cached
        if score >= 80:
            return True, score

    data = fetch_pypi_data(package)
    if not data:
        console.print(f"❌ [red]Package '{package}' not found on PyPI.[/red]")
        return False, 0

    info = data.get("info", {})
    typo_check = check_for_typosquatting(package)
    payload_passed, payload_meta = scan_payload(package, data)

    findings = {
        "Typosquatting": typo_check,
        "Identity": check_author_reputation(package, data), # <-- Add 'package' here
        "Reputation": check_reputation(package, data),
        "Resurrection": check_resurrection(data),
        "Payload": (payload_passed, payload_meta),
    }

    # Integrations: enrichment (opt-in, offline-first)
    try:
        snyk = SnykAdapter()
        snyk_enrich = snyk.enrich(package, data)
        if snyk_enrich:
            vulns = snyk_enrich.get("vulnerabilities", [])
            findings["Snyk"] = (len(vulns) == 0, vulns)
    except Exception:
        # Do not fail audit on integration errors
        pass

    try:
        socket = SocketAdapter()
        socket_enrich = socket.enrich(package, data)
        if socket_enrich:
            findings["Socket"] = (True, socket_enrich)
    except Exception:
        pass

    score = calculate_skopos_score(findings)
    cache.save_audit(package, info.get("version", "0.0.0"), score, findings)
    display_report(package, findings, score)

    return score >= 80, score


def display_report(package, results, score):
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    table = Table(
        title=f"Skopos Report: [bold]{package}[/bold] (Score: [{color}]{score}[/{color}])"
    )
    table.add_column("Heuristic", style="cyan")
    table.add_column("Status")
    table.add_column("Evidence", style="dim")
    for name, val in results.items():
        # Typosquatting is an 'inverse' check: val[0]==True means it IS a squat (a fail)
        if name == "Typosquatting":
            is_squat, target = val
            status = "[red]FAIL[/red]" if is_squat else "[green]PASS[/green]"
            evidence = f"Possible squat of: {target}" if is_squat else "None detected"
        else:
            status = "[green]PASS[/green]" if val[0] else "[red]FAIL[/red]"
            evidence = str(val[1])

        table.add_row(name, status, evidence)
    console.print(table)


# --- COMMANDS ---


def audit_project(args):
    console.print(
        Panel(
            "🔍 [bold]Skopos Project Audit[/bold]\nTarget: pyproject.toml", expand=False
        )
    )
    try:
        with open("pyproject.toml", "rb") as f:
            project_data = tomllib.load(f)
            dependencies = project_data.get("project", {}).get("dependencies", [])
            for dep_str in dependencies:
                name = (
                    dep_str.split(">")[0]
                    .split("=")[0]
                    .split("<")[0]
                    .split("[")[0]
                    .strip()
                )
                passed, score = check_package(name, args)
                if not passed:
                    console.print(
                        f"\n⚠️  [bold yellow]Risk Detected:[/bold yellow] {name} scored {score}/100"
                    )
                    choice = input(f"   Trust and whitelist {name}? (y/N): ").lower()
                    if choice == "y":
                        add_to_whitelist(name)
                        sign_whitelist()
                    else:
                        console.print(
                            "🛑 [red]Audit failed. Installation blocked.[/red]"
                        )
                        sys.exit(1)
            console.print(
                "\n✨ [bold green]Audit Complete. Environment is secure.[/bold green]"
            )
    except FileNotFoundError:
        console.print("❌ [red]pyproject.toml not found.[/red]")
        sys.exit(1)


def install_shell_hook():
    shell = os.environ.get("SHELL", "")
    rc = os.path.expanduser("~/.zshrc" if "zsh" in shell else "~/.bashrc")
    hook = f'\n# Skopos v{VERSION}\nuv() {{ if [[ "$1" == "add" ]]; then skopos check "$2" || return 1; fi; command uv "$@"; }}\n'
    with open(rc, "a") as f:
        f.write(hook)
    console.print(f"✅ Hook installed in {rc}.")


def init_config(target_path: str | None = None):
    """Write the default config template to the user's config path.

    If `target_path` is provided, write to that path (used by tests).
    Otherwise writes to `~/.skopos/config.toml` and creates the folder.
    """
    repo_root = Path(__file__).resolve().parents[2]
    default = repo_root / "etc" / "skopos_default_config.toml"
    user_cfg = Path(target_path) if target_path else Path.home() / ".skopos" / "config.toml"
    user_cfg.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(default, "rb") as src, open(user_cfg, "wb") as dst:
            dst.write(src.read())
        console.print(f"✅ Config template written to {user_cfg}")
        return True
    except Exception as e:
        console.print(f"❌ Failed to write config: {e}")
        return False


def set_integration_offline_file(provider: str, offline_path: str, target_path: str | None = None) -> bool:
    """Set `integrations.<provider>.offline_file` in the user's config.toml.

    - Creates a default config if none exists.
    - Replaces existing `offline_file` if present under the provider section.
    - Appends a provider section if missing.
    Returns True on success.
    """
    user_cfg = Path(target_path) if target_path else Path.home() / ".skopos" / "config.toml"
    user_cfg.parent.mkdir(parents=True, exist_ok=True)
    if not user_cfg.exists():
        if not init_config(target_path=str(user_cfg)):
            return False

    text = user_cfg.read_text()
    section = f"[integrations.{provider}]"
    line = f'offline_file = "{offline_path}"'
    if section in text:
        start = text.index(section)
        # find end of this section (start of next '[' after this section)
        next_sec = text.find('\n[', start + len(section))
        if next_sec == -1:
            block = text[start:]
            rest = ''
        else:
            block = text[start:next_sec]
            rest = text[next_sec:]

        if 'offline_file' in block:
            block = re.sub(r'offline_file\s*=\s*".*"', line, block)
        else:
            # append offline_file to section
            block = block.rstrip() + '\n' + line + '\n'

        new_text = text[:start] + block + rest
    else:
        # Add a new section at the end
        new_text = text.rstrip() + f"\n{section}\nenabled = false\napi_key = \"\"\noffline_file = \"{offline_path}\"\n"

    try:
        user_cfg.write_text(new_text)
        console.print(f"✅ Set {provider} offline feed to: {offline_path}")
        return True
    except Exception as e:
        console.print(f"❌ Failed to write config: {e}")
        return False


def main():
    """v0.22.0: Official Entry Point - Forensic Gatekeeper"""

    # 1. Security First: Verify Whitelist Integrity
    ensure_whitelist_exists()
    if not verify_whitelist_integrity():
        console.print("🚨 [bold red]WHITELIST TAMPERED![/bold red] Signature mismatch.")
        sys.exit(1)

    # 2. Setup Base Parser
    parser = argparse.ArgumentParser(
        prog="skopos",
        description=f"🛡️ Skopos v{VERSION}: Proactive Supply-Chain Defense",
    )

    # Add explicit version flag
    parser.add_argument("--version", action="version", version=f"Skopos v{VERSION}")

    # Global Flags
    parser.add_argument(
        "--install-hook", action="store_true", help="Install shell hooks for uv/pip"
    )
    parser.add_argument(
        "--disable", action="store_true", help="Disable and remove shell hooks"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enforce blocking mode: return non-zero exit code when audits fail (useful for CI)",
    )

    # 3. Setup Subcommands (check, audit)
    subparsers = parser.add_subparsers(dest="command", help="Skopos Forensic Commands")

    # Command: 'check'
    check_p = subparsers.add_parser("check", help="Audit a specific package from PyPI")
    check_p.add_argument("package", help="The name of the package to check")
    check_p.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Audit the entire dependency tree",
    )
    check_p.add_argument(
        "--max-depth", type=int, default=2, help="Depth for recursive auditing"
    )

    # Command: 'audit'
    audit_p = subparsers.add_parser(
        "audit", help="Audit the current project (pyproject.toml/requirements.txt)"
    )
    audit_p.add_argument(
        "--recursive", "-r", action="store_true", help="Deep audit project dependencies"
    )
    audit_p.add_argument(
        "--max-depth", type=int, default=2, help="Depth for recursive auditing"
    )

    # Command: 'config'
    config_p = subparsers.add_parser("config", help="Manage skopos configuration")
    config_p.add_argument("action", choices=["init"], help="Action to perform")

    # Command: 'integrations' (load offline feeds, etc.)
    integrations_p = subparsers.add_parser("integrations", help="Manage integrations and offline feeds")
    integ_sub = integrations_p.add_subparsers(dest="integ_cmd", help="Integration commands")

    load_snyk_p = integ_sub.add_parser("load-snyk", help="Register a local Snyk offline JSON feed and write to config")
    load_snyk_p.add_argument("path", help="Path to local Snyk JSON feed")
    load_snyk_p.add_argument("--target", help="Optional target config path (for testing)")

    demo_snyk_p = integ_sub.add_parser("demo-snyk", help="Show offline Snyk enrichment for a package without contacting PyPI")
    demo_snyk_p.add_argument("package", help="Package name to demo enrichment for")

    # 4. Parsing
    args = parser.parse_args()

    # Handle config subcommand
    if args.command == "config":
        if getattr(args, "action", None) == "init":
            init_config()
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    # Handle integrations subcommands
    if args.command == "integrations":
        if getattr(args, "integ_cmd", None) == "load-snyk":
            ok = set_integration_offline_file("snyk", args.path, getattr(args, "target", None))
            sys.exit(0 if ok else 1)
        if getattr(args, "integ_cmd", None) == "demo-snyk":
            try:
                snyk = SnykAdapter()
                enrich = snyk.enrich(args.package, {})
                if enrich:
                    console.print(enrich)
                else:
                    console.print("(no enrichment found or adapter disabled)")
            except Exception as e:
                console.print(f"Error during demo: {e}")
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(0)

    # 5. Execution Logic (The "Brain")
    if args.install_hook:
        install_shell_hook()
        sys.exit(0)

    if args.disable:
        disable_hooks()
        sys.exit(0)

    if args.command == "check":
        # Pass the package and the args namespace to the engine
        passed, score = check_package(args.package, args)
        if getattr(args, "strict", False) and not passed:
            # In strict mode we exit non-zero so shims/CI can fail fast
            sys.exit(2)
    elif args.command == "audit":
        # Pass the args namespace to the project auditor
        audit_project(args)
    else:
        # If no command and no global flag, show help
        parser.print_help()


if __name__ == "__main__":
    main()
