# tests/test_config.py
import tomllib
from pathlib import Path

from skopos.config import load_config, reset_cache
from skopos.checker import init_config


def test_load_config_defaults(tmp_path):
    reset_cache()
    cfg = load_config(path=str(tmp_path / "nonexistent.toml"))
    assert "targets" in cfg
    assert cfg["keyword_extra_chars"] == 8


def test_load_config_override(tmp_path):
    reset_cache()
    user = tmp_path / "myconf.toml"
    user.write_text('keyword_extra_chars = 2\n[targets]\nrequests = 2\n')
    cfg = load_config(path=str(user))
    assert cfg["keyword_extra_chars"] == 2
    assert cfg["targets"]["requests"] == 2


def test_init_config_writes(tmp_path):
    target = tmp_path / "config.toml"
    ok = init_config(target_path=str(target))
    assert ok is True
    assert target.exists()
    # basic sanity: it should parse as TOML
    with open(target, "rb") as f:
        parsed = tomllib.load(f)
    assert "targets" in parsed
