#!/usr/bin/env python3
"""Rebuild src/patchgap/data/feed.yaml from the distro security trackers.

Every fix entry written by this script comes from a page it fetched, and the URL of
that page is stored next to the entry. Nothing is typed in by hand except the list of
CVEs to track, their package names, and the mitigations (each with its own source URL).

Sources:
  Debian   https://security-tracker.debian.org/tracker/<CVE>        (HTML, "fixed versions" table)
  Ubuntu   https://ubuntu.com/security/cves/<CVE>.json              (JSON API)
  Red Hat  https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json
  Amazon   https://explore.alas.aws.amazon.com/<CVE>.html + linked ALAS advisories

Usage: pip install pyyaml beautifulsoup4 lxml && python scripts/build_feed.py [-o feed.yaml]
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.request

import yaml
from bs4 import BeautifulSoup

UA = {"User-Agent": "patchgap-feed-builder (+https://github.com/hamarshehmhmd/patchgap)"}
HERE = os.path.dirname(os.path.abspath(__file__))
CURATED = os.path.join(HERE, "curated.yaml")
OUT = os.path.join(os.path.dirname(HERE), "src", "patchgap", "data", "feed.yaml")

DEBIAN_RELEASES = {"bullseye", "bookworm", "trixie", "forky", "(unstable)"}
UBUNTU_LTS = {"trusty", "xenial", "bionic", "focal", "jammy", "noble", "resolute"}
UBUNTU_INTERIM = {"questing", "stonking"}


def fetch(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            if i == tries - 1:
                raise RuntimeError(f"fetch failed: {url}: {e}")
            time.sleep(3)


def debian(cve, packages):
    url = f"https://security-tracker.debian.org/tracker/{cve}"
    soup = BeautifulSoup(fetch(url), "lxml")
    out = []
    for table in soup.find_all("table"):
        head = [c.get_text(" ", strip=True) for c in table.find("tr").find_all(["th", "td"])]
        if head[:4] != ["Package", "Type", "Release", "Fixed Version"]:
            continue
        for tr in table.find_all("tr")[1:]:
            cells = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
            if len(cells) < 4:
                continue
            pkg, typ, rel, ver = cells[:4]
            origin = cells[5] if len(cells) > 5 else ""
            if pkg not in packages or rel not in DEBIAN_RELEASES:
                continue
            rel = "sid" if rel == "(unstable)" else rel
            e = {"distro": "debian", "release": rel, "package": pkg, "source": url}
            if ver == "(not affected)":
                e["status"] = "not-affected"
            elif ver == "(unfixed)":
                e["status"] = "vulnerable"
            elif re.match(r"^\d", ver):
                e["status"] = "fixed"
                e["version"] = ver
                if origin:
                    e["advisory"] = origin
            else:
                e["status"] = "unknown"
                e["note"] = ver
            out.append(e)
    # Releases that shipped after the fix have no row in the "fixed versions" table but are
    # listed as "fixed" in the first table; their versions are >= the unstable fix.
    sid_fix = {e["package"]: e["version"] for e in out if e["release"] == "sid" and e.get("version")}
    have = {(e["release"], e["package"]) for e in out}
    first = soup.find_all("table")
    for table in first:
        head = [c.get_text(" ", strip=True) for c in table.find("tr").find_all(["th", "td"])]
        if head[:4] != ["Source Package", "Release", "Version", "Status"]:
            continue
        pkg = None
        for tr in table.find_all("tr")[1:]:
            cells = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
            if len(cells) == 4:
                pkg = cells[0].split()[0] if cells[0] else pkg
                rel, status = cells[1], cells[3]
            elif len(cells) == 3:
                rel, status = cells[0], cells[2]
            else:
                continue
            rel = rel.split()[0].rstrip(",")
            if pkg in packages and rel in DEBIAN_RELEASES and status == "fixed" and \
                    (rel, pkg) not in have and pkg in sid_fix:
                have.add((rel, pkg))
                out.append({"distro": "debian", "release": rel, "package": pkg, "status": "fixed",
                            "version": sid_fix[pkg], "source": url,
                            "note": "release shipped after the fix (fixed in unstable at this version)"})
    return out


def ubuntu(cve, packages):
    url = f"https://ubuntu.com/security/cves/{cve}.json"
    page = f"https://ubuntu.com/security/{cve}"
    d = json.loads(fetch(url))
    out = []
    for p in d.get("packages", []):
        name = p["name"]
        if not any(re.fullmatch(pat, name) for pat in packages):
            continue
        for s in p["statuses"]:
            rel = s["release_codename"]
            if rel not in UBUNTU_LTS | UBUNTU_INTERIM:
                continue
            st, desc = s["status"], (s.get("description") or "").strip()
            e = {"distro": "ubuntu", "release": rel, "package": name, "source": page}
            if st == "released":
                e["status"] = "fixed"
                e["version"] = desc
                if s.get("pocket") and s["pocket"] not in ("security", "updates"):
                    e["pocket"] = s["pocket"]  # e.g. esm-infra = Ubuntu Pro
            elif st == "pending":
                # Ubuntu: "Vulnerable, work in progress in <version>" - built, not yet released.
                e["status"] = "pending"
                if desc:
                    e["version"] = desc
                e["pocket"] = "proposed"
            elif st == "needed":
                e["status"] = "vulnerable"
            elif st == "not-affected":
                e["status"] = "not-affected"
            elif st in ("DNE",):
                continue
            elif st in ("ignored", "deferred"):
                e["status"] = "vulnerable"
                e["note"] = f"ubuntu status: {st} {desc}".strip()
            else:
                e["status"] = "unknown"
                e["note"] = f"ubuntu status: {st}"
            out.append(e)
    meta = {"published": d.get("published"), "ubuntu_priority": d.get("priority"),
            "ubuntu_mitigation": (d.get("mitigation") or "").strip()}
    return out, meta


def redhat(cve, packages):
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
    page = f"https://access.redhat.com/security/cve/{cve}"
    d = json.loads(fetch(url))
    out, seen = [], set()
    for a in d.get("affected_release", []) or []:
        m = re.fullmatch(r"Red Hat Enterprise Linux (\d+)", a.get("product_name", ""))
        if not m:
            continue
        pm = re.match(r"^([a-z0-9-]+?)-(?:\d+:)?(\d.*)$", a.get("package") or "")
        if not pm or pm.group(1) not in packages:
            continue
        key = (m.group(1), pm.group(1))
        if key in seen:
            continue
        seen.add(key)
        out.append({"distro": "rhel", "release": m.group(1), "package": pm.group(1), "status": "fixed",
                    "version": pm.group(2), "advisory": a.get("advisory"), "source": page})
    for s in d.get("package_state", []) or []:
        m = re.fullmatch(r"Red Hat Enterprise Linux (\d+)", s.get("product_name", ""))
        if not m or s.get("package_name") not in packages:
            continue
        key = (m.group(1), s["package_name"])
        if key in seen:
            continue
        seen.add(key)
        st = {"Not affected": "not-affected", "Affected": "vulnerable", "Fix deferred": "vulnerable",
              "Will not fix": "vulnerable", "Under investigation": "unknown"}.get(s.get("fix_state"), "unknown")
        out.append({"distro": "rhel", "release": m.group(1), "package": s["package_name"], "status": st,
                    "note": f"red hat: {s.get('fix_state')}", "source": page})
    meta = {"redhat_severity": d.get("threat_severity"),
            "cvss3": (d.get("cvss3") or {}).get("cvss3_base_score")}
    return out, meta


def amazon(cve, packages):
    url = f"https://explore.alas.aws.amazon.com/{cve}.html"
    try:
        html = fetch(url)
    except RuntimeError:
        return []
    soup = BeautifulSoup(html, "lxml")
    out = []
    for tr in soup.find_all("tr"):
        cells = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
        if len(cells) < 5:
            continue
        platform, pkg, _date, adv, status = [re.sub(r"\s+", " ", c) for c in cells[:5]]
        if pkg not in packages:
            continue
        rel = "2023" if platform.startswith("Amazon Linux 2023") else "2" if platform.startswith("Amazon Linux 2") else None
        if rel is None:
            continue
        e = {"distro": "amzn", "release": rel, "package": pkg, "source": url}
        extra = re.search(r"Kernel-(\d+\.\d+) Extra", platform)
        if status.lower().startswith("fixed") and adv.startswith("ALAS"):
            folder = "AL2023" if rel == "2023" else "AL2"
            adv_url = f"https://alas.aws.amazon.com/{folder}/{adv}.html"
            text = BeautifulSoup(fetch(adv_url), "lxml").get_text(" ")
            name = re.escape(pkg)
            vers = re.findall(rf"\b{name}-(\d[\w.]*?-[\w.]+?)\.(?:x86_64|aarch64)\.rpm|\b{name}-(\d[\w.]*?-[\w.]+?)\.(?:x86_64|aarch64)\b", text)
            vers = [a or b for a, b in vers]
            if extra:
                vers = [v for v in vers if v.startswith(extra.group(1) + ".")]
            if not vers:
                e.update(status="unknown", note=f"{adv}: could not read fixed version")
            else:
                e.update(status="fixed", version=vers[0], advisory=adv, source=adv_url)
        elif "not affected" in status.lower():
            e["status"] = "not-affected"
        else:
            e["status"] = "vulnerable"
            e["note"] = f"amazon: {status}"
        out.append(e)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default=OUT)
    args = ap.parse_args()
    cur = yaml.safe_load(open(CURATED))
    cves = []
    for c in cur["cves"]:
        cid, pk = c["id"], c["packages"]
        print("fetching", cid, file=sys.stderr)
        fixes = debian(cid, pk.get("debian", []))
        ub, ubmeta = ubuntu(cid, pk.get("ubuntu", []))
        rh, rhmeta = redhat(cid, pk.get("rhel", []))
        fixes += ub + rh + amazon(cid, pk.get("amzn", []))
        entry = {k: v for k, v in c.items() if k != "packages"}
        entry["packages"] = pk
        entry["published"] = (ubmeta.get("published") or "")[:10] or None
        entry["severity"] = {k: v for k, v in {"cvss3": rhmeta.get("cvss3"), "redhat": rhmeta.get("redhat_severity"),
                                               "ubuntu": ubmeta.get("ubuntu_priority")}.items() if v}
        if ubmeta.get("ubuntu_mitigation"):
            entry.setdefault("notes", []).append("Ubuntu's CVE page lists a mitigation; see " +
                                                 f"https://ubuntu.com/security/{cid}")
        entry["fixes"] = fixes
        cves.append(entry)
    feed = {"schema": 1,
            "generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "generator": "scripts/build_feed.py",
            "cves": cves,
            "mitigations": cur["mitigations"]}
    with open(args.output, "w") as fh:
        fh.write("# Generated by scripts/build_feed.py from the distro trackers listed in each entry's\n"
                 "# 'source'. Do not hand-edit fix data: edit scripts/curated.yaml and re-run.\n")
        yaml.safe_dump(feed, fh, sort_keys=False, width=110, allow_unicode=True)
    n = sum(len(c["fixes"]) for c in cves)
    print(f"wrote {args.output}: {len(cves)} CVEs, {n} fix entries", file=sys.stderr)


if __name__ == "__main__":
    main()
