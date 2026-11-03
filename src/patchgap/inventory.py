"""Collect what a host is running: distro, kernel, packages, and live mitigation checks.

The same POSIX sh script runs locally or over ssh (`ssh host sh -s`), so a fleet scan
needs nothing installed on the targets."""
import datetime as dt
import json
import re
import shlex

from . import __version__

COLLECT = r'''
LC_ALL=C; export LC_ALL
echo "@@hostname"; (hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)
echo "@@os-release"; cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null
echo "@@uname-r"; uname -r
echo "@@uname-v"; uname -v
echo "@@uname-m"; uname -m
echo "@@uid"; id -u
if command -v dpkg-query >/dev/null 2>&1; then
  echo "@@pkgs-deb"
  dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3"\t"$4}'
fi
if command -v rpm >/dev/null 2>&1 && ! command -v dpkg-query >/dev/null 2>&1; then
  echo "@@pkgs-rpm"
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n' 2>/dev/null
fi
echo "@@builtin"; cat "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null | sed 's#.*/##; s#\.ko.*##'
echo "@@loaded"; cut -d' ' -f1 /proc/modules 2>/dev/null
echo "@@kconfig"; grep -E '^(CONFIG_CRYPTO_USER_API_AEAD|CONFIG_MPTCP|CONFIG_NF_TABLES)=' "/boot/config-$(uname -r)" 2>/dev/null
echo "@@checks"
'''


def checks_script(feed):
    """Shell snippets that print '<mitigation-id> yes|no|unknown' for each mitigation."""
    lines = []
    for m in feed.get("mitigations", []):
        mid = m["id"]
        q = shlex.quote
        if m["kind"] == "nftables":
            t = m["table"]
            test = f"nft list table {q(t['family'])} {q(t['name'])} >/dev/null 2>&1"
            lines.append(f"if [ \"$(id -u)\" != 0 ] || ! command -v nft >/dev/null 2>&1; then echo {mid} unknown; "
                         f"elif {test}; then echo {mid} yes; else echo {mid} no; fi")
        elif m["kind"] == "modprobe":
            conds = " && ".join(
                f"modprobe -n -v {q(mod)} 2>&1 | grep -q /bin/false && ! grep -q '^{mod} ' /proc/modules"
                for mod in m["modules"])
            lines.append(f"if ! command -v modprobe >/dev/null 2>&1; then echo {mid} unknown; "
                         f"elif {conds}; then echo {mid} yes; else echo {mid} no; fi")
        elif m["kind"] == "sshd":
            greps = " && ".join(f"echo \"$o\" | grep -qix {q(k.lower() + ' ' + str(v))}"
                                for k, v in m["directives"].items())
            lines.append(f"if [ \"$(id -u)\" != 0 ] || ! command -v sshd >/dev/null 2>&1; then echo {mid} unknown; "
                         f"else o=$(sshd -T 2>/dev/null); if [ -n \"$o\" ] && {greps}; then echo {mid} yes; "
                         f"else echo {mid} no; fi; fi")
        elif m["kind"] == "sysctl":
            conds = " && ".join(f"[ \"$(sysctl -n {q(k)} 2>/dev/null)\" = {q(str(v))} ]"
                                for k, v in m["settings"].items())
            lines.append(f"if {conds}; then echo {mid} yes; else echo {mid} no; fi")
    return "\n".join(lines) + "\n"


def script(feed):
    return COLLECT + checks_script(feed)


def parse_os_release(text):
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if m:
            v = m.group(2).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[m.group(1)] = v
    return out


def parse(text):
    """Turn the collector's output into an inventory dict."""
    sections, cur = {}, None
    for line in text.splitlines():
        if line.startswith("@@"):
            cur = line[2:].strip()
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    osr = parse_os_release("\n".join(sections.get("os-release", [])))
    pkgs, fmt = [], None
    for key, f in (("pkgs-deb", "deb"), ("pkgs-rpm", "rpm")):
        if key in sections:
            fmt = f
            for line in sections[key]:
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0]:
                    name, ver = parts[0], parts[1]
                    if f == "rpm" and ver.startswith("0:"):
                        ver = ver[2:]
                    src = parts[2] if len(parts) > 2 and parts[2] else name
                    if f == "rpm":
                        src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", src)
                    pkgs.append({"name": name, "version": ver, "source": src})
    checks = {}
    for line in sections.get("checks", []):
        parts = line.split()
        if len(parts) == 2:
            checks[parts[0]] = parts[1]
    first = lambda k: (sections.get(k) or [""])[0].strip()  # noqa: E731
    uid = first("uid")
    return {
        "patchgap": __version__,
        "collected": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "host": first("hostname") or "unknown",
        "os": {"id": osr.get("ID", "unknown"), "version_id": osr.get("VERSION_ID", ""),
               "codename": osr.get("VERSION_CODENAME") or osr.get("UBUNTU_CODENAME", ""),
               "id_like": osr.get("ID_LIKE", ""), "pretty": osr.get("PRETTY_NAME", "")},
        "kernel": {"release": first("uname-r"), "version": first("uname-v"), "machine": first("uname-m")},
        "root": uid == "0",
        "package_format": fmt,
        "packages": pkgs,
        "builtin_modules": [x.strip() for x in sections.get("builtin", []) if x.strip()],
        "loaded_modules": [x.strip() for x in sections.get("loaded", []) if x.strip()],
        "kconfig": dict(x.split("=", 1) for x in sections.get("kconfig", []) if "=" in x),
        "mitigation_checks": checks,
    }


def collect_local(feed, runner):
    r = runner.run(["sh", "-c", script(feed)])
    if not r.out.strip():
        raise RuntimeError(f"inventory failed: {r.err.strip()}")
    return parse(r.out)


def collect_ssh(host, feed, runner, ssh_opts=None):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"] + list(ssh_opts or []) + [host, "sh", "-s"]
    r = runner.run(cmd, input=script(feed), timeout=180)
    if "@@os-release" not in r.out:
        raise RuntimeError(f"{host}: ssh failed (rc {r.rc}): {r.err.strip()[:300]}")
    inv = parse(r.out)
    inv["target"] = host
    return inv


def load(path):
    with open(path) as fh:
        data = json.load(fh)
    items = data if isinstance(data, list) else [data]
    for inv in items:
        if "os" not in inv or "kernel" not in inv:
            raise ValueError(f"{path}: not a patchgap inventory (missing os/kernel)")
        inv.setdefault("packages", [])
        inv.setdefault("mitigation_checks", {})
        inv.setdefault("builtin_modules", [])
        inv.setdefault("loaded_modules", [])
        inv.setdefault("kconfig", {})
    return items
