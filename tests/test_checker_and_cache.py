import json
import os
from pathlib import Path

import pytest

from skopos import checker
from skopos.cache import CacheManager


def test_whitelist_lifecycle(tmp_path, monkeypatch):
    # Redirect whitelist and sig files to tmp path
    wl = tmp_path / "whitelist"
    sig = tmp_path / "whitelist.sig"
    monkeypatch.setattr(checker, "WHITELIST_FILE", str(wl))
    monkeypatch.setattr(checker, "SIG_FILE", str(sig))

    # Ensure creation
    checker.ensure_whitelist_exists()
    assert wl.exists()
    assert checker.verify_whitelist_integrity()

    # Add package and sign
    checker.add_to_whitelist("examplepkg")
    checker.sign_whitelist()
    assert checker.is_whitelisted("examplepkg")

    # Tamper file and verify integrity fails
    wl.write_text("tampered")
    assert not checker.verify_whitelist_integrity()


def test_check_velocity_and_resurrection(tmp_path):
    # many releases -> velocity flag
    data_many = {"releases": {str(i): [] for i in range(30)}}
    status, meta = checker.check_velocity(data_many)
    assert status is False and meta.get("releases") >= 20

    # few releases -> delegated to resurrection and includes releases count
    data_few = {"releases": {"0.1": [{"upload_time": "2020-01-01T00:00:00Z"}]}}
    status2, meta2 = checker.check_velocity(data_few)
    assert isinstance(meta2.get("releases"), int)


def test_init_config_and_set_integration_offline_file(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.toml"
    # init_config should write default template
    ok = checker.init_config(target_path=str(cfg_path))
    assert ok and cfg_path.exists()

    # Now set offline file for snyk
    offline_json = tmp_path / "snyk.json"
    offline_json.write_text("{}")
    ok2 = checker.set_integration_offline_file("snyk", str(offline_json), target_path=str(cfg_path))
    assert ok2
    text = cfg_path.read_text()
    assert "offline_file" in text


def test_cache_manager_roundtrip(tmp_path):
    db = tmp_path / "cache.db"
    cm = CacheManager(db_path=str(db))
    # Initially empty
    assert cm.get_cached_audit("pkg", "1.0") is None

    cm.save_audit("pkg", "1.0", 90, {"meta": True})
    got = cm.get_cached_audit("pkg", "1.0")
    assert got is not None
    score, meta = got
    assert score == 90 and meta.get("meta") is True


def test_snyk_adapter_offline(monkeypatch, tmp_path):
    # Prepare offline feed
    feed = {"mypkg": [{"id": "CVE-123"}]}
    feed_path = tmp_path / "snyk_feed.json"
    feed_path.write_text(json.dumps(feed))

    # Monkeypatch load_config used by the adapter module
    import skopos.integrations.snyk_adapter as sa

    monkeypatch.setattr(sa, "load_config", lambda: {"integrations": {"snyk": {"enabled": True, "api_key": "", "offline_file": str(feed_path)}}})
    adapter = sa.SnykAdapter()
    assert adapter.is_enabled()
    enriched = adapter.enrich("mypkg", {})
    assert isinstance(enriched, dict) and "vulnerabilities" in enriched
