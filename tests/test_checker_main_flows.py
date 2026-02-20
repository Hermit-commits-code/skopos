import os
import sys
from pathlib import Path
import builtins
import json
import hashlib

import pytest
import types

from skopos import checker


def make_whitelist(tmp_path):
    wl = tmp_path / "whitelist"
    sig = tmp_path / "whitelist.sig"
    wl.write_text("# trust\n")
    with open(wl, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    sig.write_text(h)
    return str(wl), str(sig)


def test_main_config_init_creates_file(tmp_path, monkeypatch):
    # Prepare isolated home and whitelist
    monkeypatch.setenv("HOME", str(tmp_path))
    wl, sig = make_whitelist(tmp_path)
    monkeypatch.setattr(checker, "WHITELIST_FILE", wl)
    monkeypatch.setattr(checker, "SIG_FILE", sig)

    # Run main with config init
    monkeypatch.setattr(sys, "argv", ["skopos", "config", "init"])
    with pytest.raises(SystemExit) as se:
        checker.main()
    assert se.value.code == 0
    # Default config written to ~/.skopos/config.toml
    cfg = Path(tmp_path) / ".skopos" / "config.toml"
    assert cfg.exists()


def test_main_integrations_demo_snyk_prints_enrich(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    wl, sig = make_whitelist(tmp_path)
    monkeypatch.setattr(checker, "WHITELIST_FILE", wl)
    monkeypatch.setattr(checker, "SIG_FILE", sig)

    # Fake SnykAdapter to return enrichment
    class FakeSnyk:
        def enrich(self, package, metadata):
            return {"vulnerabilities": [{"id": "CVE-1"}]}

    monkeypatch.setattr(checker, "SnykAdapter", lambda: FakeSnyk())
    monkeypatch.setattr(sys, "argv", ["skopos", "integrations", "demo-snyk", "mypkg"])
    with pytest.raises(SystemExit) as se:
        checker.main()
    assert se.value.code == 0


def test_install_and_disable_hooks(tmp_path, monkeypatch):
    # Use temporary HOME so installs write to tmp rc files
    monkeypatch.setenv("HOME", str(tmp_path))
    wl, sig = make_whitelist(tmp_path)
    monkeypatch.setattr(checker, "WHITELIST_FILE", wl)
    monkeypatch.setattr(checker, "SIG_FILE", sig)

    # Install hook
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(sys, "argv", ["skopos", "--install-hook"])
    with pytest.raises(SystemExit) as se:
        checker.main()
    assert se.value.code == 0
    rc = Path(tmp_path) / ".bashrc"
    assert rc.exists()
    assert "uv()" in rc.read_text()

    # Now test disable removes lines
    # Add a Skopos line to rc
    rc.write_text(rc.read_text() + "\n# Skopos test entry uv() { command uv }\n")
    monkeypatch.setattr(sys, "argv", ["skopos", "--disable"])
    with pytest.raises(SystemExit) as se2:
        checker.main()
    # disable_hooks prints but does not exit with non-zero
    assert se2.value.code == 0
    assert "Skopos" not in rc.read_text()


def test_audit_project_interactive_blocks_on_fail(tmp_path, monkeypatch):
    # Create a minimal pyproject.toml with one dependency
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "pyproject.toml"
    p.write_text("[project]\nname = \"demo\"\ndependencies = [\"nonexistentpkg==0.0\"]\n")

    # Ensure whitelist ok
    wl, sig = make_whitelist(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(checker, "WHITELIST_FILE", wl)
    monkeypatch.setattr(checker, "SIG_FILE", sig)

    # Monkeypatch check_package to return fail
    monkeypatch.setattr(checker, "check_package", lambda name, args: (False, 10))
    # Simulate user answering 'n' to whitelist prompt
    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")

    with pytest.raises(SystemExit) as se:
        checker.audit_project(types.SimpleNamespace())
    assert se.value.code == 1