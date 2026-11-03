import copy
import re

import pytest
import yaml

from patchgap import feed as feedmod


def test_bundled_feed_validates_and_every_fix_has_a_source():
    f = feedmod.load(feedmod.BUNDLED)
    assert len(f["cves"]) >= 3
    for c in f["cves"]:
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", c["id"])
        assert c["references"], c["id"]
        for fx in c["fixes"]:
            assert fx["source"].startswith("https://"), fx
            if fx["status"] == "fixed":
                assert fx["version"]
    for m in f["mitigations"]:
        assert m["sources"] and all(s.startswith("https://") for s in m["sources"])


def test_bundled_feed_sources_match_trackers():
    f = feedmod.load(feedmod.BUNDLED)
    hosts = {"debian": "security-tracker.debian.org", "ubuntu": "ubuntu.com",
             "rhel": "access.redhat.com", "amzn": "alas.aws.amazon.com"}
    for c in f["cves"]:
        for fx in c["fixes"]:
            assert hosts[fx["distro"]] in fx["source"], fx
            assert c["id"] in fx["source"] or fx["source"].endswith(".html"), fx


def test_validate_rejects_missing_source(feed):
    bad = copy.deepcopy({k: v for k, v in feed.items() if k != "_path"})
    del bad["cves"][0]["fixes"][0]["source"]
    with pytest.raises(feedmod.FeedError, match="source"):
        feedmod.validate(bad)


def test_validate_rejects_fixed_without_version(feed):
    bad = copy.deepcopy({k: v for k, v in feed.items() if k != "_path"})
    del bad["cves"][0]["fixes"][0]["version"]
    with pytest.raises(feedmod.FeedError, match="version"):
        feedmod.validate(bad)


def test_validate_rejects_unknown_mitigation(feed):
    bad = copy.deepcopy({k: v for k, v in feed.items() if k != "_path"})
    bad["cves"][0]["mitigations"] = ["nope"]
    with pytest.raises(feedmod.FeedError):
        feedmod.validate(bad)


def test_update_from_url_caches_only_valid(tmp_path, feed):
    good = open(feed["_path"]).read()
    dest = tmp_path / "cache" / "feed.yaml"
    path, f = feedmod.update("https://example.invalid/feed.yaml", str(dest), opener=lambda u: good)
    assert dest.read_text() == good and f["cves"]
    with pytest.raises(feedmod.FeedError):
        feedmod.update("https://example.invalid/feed.yaml", str(dest), opener=lambda u: "schema: 2\n")
    assert dest.read_text() == good  # old cache kept


def test_update_from_local_file(tmp_path, feed):
    dest = tmp_path / "f.yaml"
    feedmod.update(feed["_path"], str(dest))
    assert yaml.safe_load(dest.read_text())["schema"] == 1


def test_load_prefers_cache(tmp_path, monkeypatch, feed):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert feedmod.load()["_path"] == feedmod.BUNDLED
    (tmp_path / "patchgap").mkdir()
    (tmp_path / "patchgap" / "feed.yaml").write_text(open(feed["_path"]).read())
    assert feedmod.load()["_path"] == str(tmp_path / "patchgap" / "feed.yaml")
