from datetime import datetime, timedelta

import pytest

from skopos import checker_logic as cl


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("kitten", "sitting", 3),
        ("", "abc", 3),
        ("same", "same", 0),
    ],
)
def test_levenshtein_distance_basic(a, b, expected):
    assert cl.levenshtein_distance(a, b) == expected


def test_calculate_entropy_empty_and_varied():
    assert cl.calculate_entropy("") == 0.0
    assert cl.calculate_entropy("aaaaaa") == 0.0
    ent = cl.calculate_entropy("abcABC123!")
    assert ent > 1.0


def test_check_for_typosquatting_custom_targets():
    targets = {"requests": 1}
    assert cl.check_for_typosquatting("request", custom_targets=targets)[0]
    assert cl.check_for_typosquatting("requests-extra", custom_targets={"requests": 1})[0]
    assert not cl.check_for_typosquatting("unrelatedpkg", custom_targets=targets)[0]


def test_get_dependencies_and_uniqueness():
    data = {
        "info": {
            "requires_dist": [
                "requests>=2.0",
                "urllib3; extra == 'security'",
                "PyYAML (==5.4)",
                "requests",
            ]
        }
    }
    deps = cl.get_dependencies(data)
    assert "requests" in deps
    assert "pyyaml" in deps
    assert "urllib3" not in deps


def test_calculate_skopos_score_typo_and_weights():
    res = {"Typosquatting": (True, "requests")}
    assert cl.calculate_skopos_score(res) == 0

    res2 = {"Resurrection": (False, {}), "Payload": (False, {}), "Obfuscation": (False, {})}
    score = cl.calculate_skopos_score(res2)
    assert 0 <= score <= 100 and score < 100


def test_check_resurrection_new_and_dormant():
    ok, info = cl.check_resurrection({"releases": {}})
    assert ok is True and info.get("status") == "New"

    now = datetime.utcnow()
    old = (now - timedelta(days=750)).replace(microsecond=0).isoformat() + "Z"
    recent = (now - timedelta(days=1)).replace(microsecond=0).isoformat() + "Z"
    releases = {"0.1": [{"upload_time": old}], "1.0": [{"upload_time": recent}]}
    ok2, info2 = cl.check_resurrection({"releases": releases})
    assert ok2 is False and info2.get("max_gap") > 730


def test_check_author_reputation_missing_and_brand():
    data_missing = {"info": {"author": "Alice", "author_email": ""}, "releases": {}}
    ok, info = cl.check_author_reputation("mypkg", data_missing)
    assert ok is False and "Missing author email" in info.get("reason")

    data_brand = {"info": {"author": "Bob", "author_email": "bob@example.com"}, "releases": {}}
    ok2, info2 = cl.check_author_reputation("google-tools", data_brand)
    assert ok2 is False and "Suspected" in info2.get("reason")


def test_scan_payload_detects_suspicious_and_entropy():
    unique_chars = "".join(chr(33 + i) for i in range(40))
    data = {
        "info": {"version": "1.0"},
        "releases": {"1.0": [{"filename": "good.txt"}, {"filename": "bad.exe"}, {"filename": unique_chars}]},
    }
    passed, info = cl.scan_payload("pkg", data)
    assert not passed
    assert "bad.exe" in info.get("suspicious") or info.get("suspicious")


def test_check_identity_alias_and_check_for_updates_offline(monkeypatch):
    data = {"info": {"author": "Eve", "author_email": "eve@example.com"}, "releases": {}}
    assert cl.check_identity("mypkg", data) == cl.check_author_reputation("mypkg", data)

    import requests

    def raise_exc(*a, **k):
        raise Exception("offline")

    monkeypatch.setattr(requests, "get", raise_exc)
    ok, ver = cl.check_for_updates("0.0.1")
    assert ok is True and ver == "0.0.1"
