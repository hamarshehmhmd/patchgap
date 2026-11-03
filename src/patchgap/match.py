"""Decide, per host and CVE, whether the running system is exposed."""
import re

from .versions import compare, scheme_for

# Result states
FIXED = "fixed"                    # running version >= fixed version
NOT_AFFECTED = "not-affected"      # distro says this release is not affected
NOT_INSTALLED = "not-installed"    # package not present
REBOOT = "reboot-required"         # fixed kernel installed but not running
FIX_AVAILABLE = "fix-available"    # fix released, not installed
FIX_PENDING = "fix-pending"        # fix built but only in a pre-release pocket (Ubuntu -proposed)
NO_FIX = "no-fix"                  # distro lists the release as vulnerable with no fix
UNKNOWN = "unknown"                # feed has no data for this distro/release/package

EXPOSED = {REBOOT, FIX_AVAILABLE, FIX_PENDING, NO_FIX}


def series(v):
    m = re.match(r"^(?:\d+:)?(\d+\.\d+)", v or "")
    return m.group(1) if m else None


def release_key(inv):
    os_ = inv["os"]
    distro = os_.get("id", "")
    if distro in ("debian", "ubuntu"):
        rel = os_.get("codename", "")
        if distro == "debian" and not rel:
            rel = "sid"
    else:
        rel = (os_.get("version_id") or "").split(".")[0]
    if distro in ("rocky", "almalinux", "centos", "ol"):
        distro = distro  # not in the feed: reported as unknown, never guessed from RHEL
    return distro, rel


def running_kernel_version(inv):
    """Map uname output to the distro package version scheme."""
    distro = inv["os"].get("id")
    r, v = inv["kernel"].get("release", ""), inv["kernel"].get("version", "")
    if distro == "debian":
        m = re.search(r"Debian (\S+)", v)
        return m.group(1) if m else None
    if distro == "ubuntu":
        m = re.match(r"^(\d+\.\d+\.\d+-\d+)", r)
        u = re.match(r"^#(\S+?)-Ubuntu", v)
        if m and u:
            return f"{m.group(1)}.{u.group(1)}"
        return None
    return re.sub(r"\.(x86_64|aarch64|ppc64le|s390x|i686|armv7hl|noarch)$", "", r) or None


def ubuntu_flavour(inv):
    m = re.match(r"^\d+\.\d+\.\d+-\d+-(.+)$", inv["kernel"].get("release", ""))
    return m.group(1) if m else "generic"


def _name_series(distro, pkg):
    pat = {"ubuntu": r"-(\d+\.\d+)$", "debian": r"^linux-(\d+\.\d+)$", "amzn": r"^kernel(\d+\.\d+)$"}.get(distro)
    m = re.search(pat, pkg) if pat else None
    return m.group(1) if m else None


def _pick(distro, entries, run_series):
    """Pick the fix entry for the running kernel series.

    An entry's series comes from its package name (linux-hwe-6.8, linux-6.12, kernel6.12) or
    from its version. If nothing matches, fall back to the one entry that has neither (e.g. a
    plain 'linux' marked vulnerable with no version)."""
    scored = [(_name_series(distro, e["package"]) or series(e.get("version")), e) for e in entries]
    exact = [e for s, e in scored if s and s == run_series]
    if exact:
        return exact[0]
    loose = [e for s, e in scored if s is None]
    return loose[0] if len(loose) == 1 else None


def _fixes(cve, distro, rel):
    return [f for f in cve.get("fixes", []) if f["distro"] == distro and str(f["release"]) == str(rel)]


def kernel_entry(cve, inv):
    distro, rel = release_key(inv)
    fixes = _fixes(cve, distro, rel)
    running = running_kernel_version(inv)
    rs = series(running) or series(inv["kernel"].get("release"))
    if distro == "ubuntu":
        fl = ubuntu_flavour(inv)
        generic = fl.startswith("generic")
        base = "linux" if generic else f"linux-{fl}"
        extra = r"linux-hwe-\d+\.\d+" if generic else re.escape(base) + r"-\d+\.\d+"
        fixes = [f for f in fixes if f["package"] == base or re.fullmatch(extra, f["package"])]
    return _pick(distro, fixes, rs), running


def installed_kernels(inv):
    """Versions of installed kernel image packages (to spot 'fixed but not rebooted')."""
    out = []
    for p in inv.get("packages", []):
        n = p["name"]
        if inv.get("package_format") == "deb":
            if re.match(r"^linux-image-\d", n) and not n.startswith("linux-image-unsigned"):
                out.append(p["version"])
        elif n in ("kernel", "kernel-core") or re.match(r"^kernel\d+\.\d+$", n):
            out.append(p["version"].split(":", 1)[-1])
    return out


def assess(cve, inv):
    distro, rel = release_key(inv)
    scheme = scheme_for(distro)
    res = {"cve": cve["id"], "name": cve.get("name"), "distro": distro, "release": rel}
    if cve["component"] == "kernel":
        entry, running = kernel_entry(cve, inv)
        res["running"] = running or inv["kernel"].get("release")
        res["component"] = "kernel"
        if running is None:
            res.update(state=UNKNOWN, reason=f"running kernel {inv['kernel'].get('release')} is not a "
                       f"{distro} package build (custom/vendor kernel); check it with its vendor")
            return res
    else:
        names = (cve.get("binaries") or {}).get(inv.get("package_format") or "deb", [])
        inst = [p for p in inv.get("packages", []) if p["name"] in names]
        res["component"] = ",".join(names)
        if not inst:
            res.update(state=NOT_INSTALLED, reason=f"{'/'.join(names)} not installed")
            return res
        running = inst[0]["version"]
        res["running"] = running
        src = inst[0].get("source") or inst[0]["name"]
        fixes = [f for f in _fixes(cve, distro, rel) if f["package"] == src] or _fixes(cve, distro, rel)
        entry = fixes[0] if fixes else None
    if entry is None:
        res.update(state=UNKNOWN, reason=f"feed has no data for {distro} {rel}" +
                   (f" ({res.get('running')})" if res.get("running") else ""))
        return res
    res["package"] = entry["package"]
    res["source"] = entry["source"]
    if entry.get("advisory"):
        res["advisory"] = entry["advisory"]
    st, fv = entry["status"], entry.get("version")
    if fv:
        res["fixed_version"] = fv
    if st == "not-affected":
        res.update(state=NOT_AFFECTED, reason=f"{distro} lists {rel} as not affected")
        return res
    if st == "unknown" or (st in ("fixed", "pending") and not fv):
        res.update(state=UNKNOWN, reason=entry.get("note") or "fix status unknown")
        return res
    if fv and running and compare(running, fv, scheme) >= 0:
        res.update(state=FIXED, reason=f"running {running} >= {fv}" + (" (from -proposed)" if st == "pending" else ""))
        return res
    if cve["component"] == "kernel" and fv:
        newer = [k for k in installed_kernels(inv) if series(k) == series(fv) and compare(k, fv, scheme) >= 0]
        if newer:
            res.update(state=REBOOT, installed=max(newer, key=lambda x: x), reason=f"fixed kernel {newer[0]} installed; reboot into it")
            return res
    if st == "fixed":
        pocket = entry.get("pocket")
        res.update(state=FIX_AVAILABLE, reason=f"update to {fv}" + (f" (needs {pocket})" if pocket else ""))
    elif st == "pending":
        res.update(state=FIX_PENDING, reason=f"fix {fv} is only in {entry.get('pocket', 'a pre-release')} pocket")
    else:
        res.update(state=NO_FIX, reason=f"{distro} {rel}: vulnerable, no fix released yet" +
                   (f" ({entry['note']})" if entry.get("note") else ""))
    return res


def mitigation_state(feed, cve, inv, state):
    """Combine live checks from the inventory with the local state file."""
    out = []
    applied = (state or {}).get("applied", {})
    for mid in cve.get("mitigations", []) or []:
        live = inv.get("mitigation_checks", {}).get(mid, "unknown")
        out.append({"id": mid, "active": live, "recorded": mid in applied})
    return out


def report(feed, inv, state=None, only=None):
    rows = []
    for c in feed.get("cves", []):
        if only and c["id"].upper() not in {o.upper() for o in only}:
            continue
        r = assess(c, inv)
        r["mitigations"] = mitigation_state(feed, c, inv, state)
        r["exposed"] = r["state"] in EXPOSED
        r["mitigated"] = r["exposed"] and any(m["active"] == "yes" for m in r["mitigations"])
        rows.append(r)
    return {"host": inv.get("target") or inv.get("host"), "os": inv["os"].get("pretty") or
            f"{inv['os'].get('id')} {inv['os'].get('version_id')}", "kernel": inv["kernel"].get("release"),
            "results": rows}


def exit_code(reports):
    """0 nothing exposed, 1 exposed and unmitigated, 2 exposed but every exposure mitigated."""
    exposed = [r for rep in reports for r in rep["results"] if r["exposed"]]
    if not exposed:
        return 0
    return 2 if all(r["mitigated"] for r in exposed) else 1
