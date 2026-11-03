"""Load, validate and update the CVE feed."""
import os
import urllib.request

import yaml

BUNDLED = os.path.join(os.path.dirname(__file__), "data", "feed.yaml")
DEFAULT_URL = "https://raw.githubusercontent.com/hamarshehmhmd/patchgap/main/src/patchgap/data/feed.yaml"
STATUSES = {"fixed", "pending", "vulnerable", "not-affected", "unknown"}
KINDS = {"nftables", "modprobe", "sshd", "sysctl"}


class FeedError(ValueError):
    pass


def cache_path():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "patchgap", "feed.yaml")


def validate(feed):
    if not isinstance(feed, dict) or feed.get("schema") != 1:
        raise FeedError("feed: missing 'schema: 1'")
    mids = {}
    for m in feed.get("mitigations", []) or []:
        if m.get("kind") not in KINDS:
            raise FeedError(f"mitigation {m.get('id')}: unknown kind {m.get('kind')!r}")
        if not m.get("sources"):
            raise FeedError(f"mitigation {m['id']}: needs at least one source URL")
        need = {"nftables": ("table", "ruleset"), "modprobe": ("modules",), "sshd": ("directives",),
                "sysctl": ("settings",)}[m["kind"]]
        for k in need:
            if not m.get(k):
                raise FeedError(f"mitigation {m['id']}: missing {k}")
        mids[m["id"]] = m
    for c in feed.get("cves", []) or []:
        if not str(c.get("id", "")).startswith("CVE-"):
            raise FeedError(f"bad CVE id {c.get('id')!r}")
        if c.get("component") not in ("kernel", "package"):
            raise FeedError(f"{c['id']}: component must be kernel or package")
        for mid in c.get("mitigations", []) or []:
            if mid not in mids:
                raise FeedError(f"{c['id']}: unknown mitigation {mid}")
        for f in c.get("fixes", []) or []:
            if f.get("status") not in STATUSES:
                raise FeedError(f"{c['id']}: bad status {f.get('status')!r}")
            if not str(f.get("source", "")).startswith("http"):
                raise FeedError(f"{c['id']} {f.get('distro')}/{f.get('release')}: every fix needs a source URL")
            if f["status"] == "fixed" and not f.get("version"):
                raise FeedError(f"{c['id']} {f['distro']}/{f['release']}: fixed without a version")
    return feed


def parse(text):
    try:
        return validate(yaml.safe_load(text))
    except yaml.YAMLError as e:
        raise FeedError(f"feed is not valid YAML: {e}")


def load(path=None):
    """--feed path, else the cached update (if any), else the bundled feed."""
    if path is None:
        cp = cache_path()
        path = cp if os.path.exists(cp) else BUNDLED
    with open(path) as fh:
        feed = parse(fh.read())
    feed["_path"] = path
    return feed


def update(url=DEFAULT_URL, dest=None, opener=None):
    dest = dest or cache_path()
    if url.startswith(("http://", "https://")):
        opener = opener or (lambda u: urllib.request.urlopen(
            urllib.request.Request(u, headers={"User-Agent": "patchgap"}), timeout=60).read().decode())
        text = opener(url)
    else:
        with open(url) as fh:
            text = fh.read()
    feed = parse(text)  # refuse to cache anything that does not validate
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, dest)
    return dest, feed


def mitigation(feed, mid):
    for m in feed.get("mitigations", []):
        if m["id"] == mid:
            return m
    return None


def cve(feed, cid):
    for c in feed.get("cves", []):
        if c["id"].upper() == cid.upper():
            return c
    return None
