import pytest
from skopos.integrations.snyk_adapter import SnykAdapter
from skopos.integrations.socket_adapter import SocketAdapter
from skopos.config import reset_cache, load_config


def test_adapters_disabled_by_default(tmp_path, monkeypatch):
    # Ensure config cache reset
    reset_cache()
    # load defaults
    cfg = load_config()
    assert not cfg.get("integrations", {}).get("snyk", {}).get("enabled", False)
    assert not cfg.get("integrations", {}).get("socket", {}).get("enabled", False)

    snyk = SnykAdapter()
    socket = SocketAdapter()

    assert not snyk.is_enabled()
    assert not socket.is_enabled()
    assert snyk.enrich("requests", {}) == {}
    assert socket.enrich("requests", {}) == {}
