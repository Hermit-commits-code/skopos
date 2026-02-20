import types
import json

import pytest

from skopos import checker


def test_display_report_smoke(capsys):
    results = {
        "Typosquatting": (False, None),
        "Identity": (True, {}),
        "Payload": (True, {}),
    }
    # should not raise
    checker.display_report("example", results, 85)
    captured = capsys.readouterr()
    assert "Skopos Report" in captured.out


def test_check_package_whitelisted(monkeypatch):
    monkeypatch.setattr(checker, "is_whitelisted", lambda n: True)
    ok, score = checker.check_package("whatever", None)
    assert ok is True and score == 100


def test_check_package_cached_high_score(monkeypatch):
    monkeypatch.setattr(checker.cache, "get_cached_audit", lambda pkg, ver: (85, {}))
    ok, score = checker.check_package("whatever", None)
    assert ok is True and score == 85


def test_check_package_not_found(monkeypatch, capsys):
    monkeypatch.setattr(checker, "is_whitelisted", lambda n: False)
    monkeypatch.setattr(checker.cache, "get_cached_audit", lambda pkg, ver: None)
    monkeypatch.setattr(checker, "fetch_pypi_data", lambda pkg: None)
    ok, score = checker.check_package("missing-pkg", None)
    assert ok is False and score == 0


def test_check_package_with_snyk_and_socket(monkeypatch):
    # Prepare fake pypi data
    data = {"info": {"version": "1.2.3"}, "releases": {"1.2.3": [{"filename": "a.txt", "upload_time": "2026-02-19T00:00:00Z"}]}}
    monkeypatch.setattr(checker, "is_whitelisted", lambda n: False)
    monkeypatch.setattr(checker.cache, "get_cached_audit", lambda pkg, ver: None)
    monkeypatch.setattr(checker, "fetch_pypi_data", lambda pkg: data)

    class FakeSnyk:
        def enrich(self, package, metadata):
            return {"vulnerabilities": [{"id": "CVE-1"}]}

    class FakeSocket:
        def enrich(self, package, metadata):
            return {"meta": True}

    monkeypatch.setattr(checker, "SnykAdapter", lambda: FakeSnyk())
    monkeypatch.setattr(checker, "SocketAdapter", lambda: FakeSocket())

    saved = {}

    def fake_save(pkg, ver, score, findings):
        saved.update({"pkg": pkg, "ver": ver, "score": score})

    monkeypatch.setattr(checker.cache, "save_audit", fake_save)

    ok, score = checker.check_package("somepkg", None)
    # Snyk vulnerability should lower score below 80
    assert ok is False and score < 80
    assert saved.get("ver") == "1.2.3"
