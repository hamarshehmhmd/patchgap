"""Version comparison: dpkg (Debian/Ubuntu) and rpmvercmp (RHEL/Amazon Linux)."""
import re


def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) else 0
            bc = _deb_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _deb_split(v):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e or 0)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def deb_cmp(a, b):
    """Compare two Debian versions. Returns <0, 0, >0 like dpkg --compare-versions."""
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _deb_part(ua, ub)
    if r:
        return -1 if r < 0 else 1
    r = _deb_part(ra, rb)
    return 0 if r == 0 else (-1 if r < 0 else 1)


_RPM_SEG = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def _rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    while True:
        # skip separators
        while i < len(a) and not (a[i].isalnum() or a[i] in "~^"):
            i += 1
        while j < len(b) and not (b[j].isalnum() or b[j] in "~^"):
            j += 1
        # tilde sorts before everything
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        # caret sorts after end, before anything else
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        if a[i].isdigit():
            m1 = re.match(r"\d+", a[i:]).group()
            m2 = re.match(r"\d+", b[j:]).group() if b[j].isdigit() else None
            if m2 is None:
                return 1
            isnum = True
        else:
            m1 = re.match(r"[a-zA-Z]+", a[i:]).group()
            m2 = re.match(r"[a-zA-Z]+", b[j:]).group() if b[j].isalpha() else None
            if m2 is None:
                return -1
            isnum = False
        i += len(m1)
        j += len(m2)
        if isnum:
            x, y = m1.lstrip("0"), m2.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        else:
            x, y = m1, m2
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _evr(v):
    v = v.strip()
    epoch = "0"
    if ":" in v:
        epoch, v = v.split(":", 1)
    if "-" in v:
        ver, rel = v.split("-", 1)
    else:
        ver, rel = v, ""
    return epoch or "0", ver, rel


def rpm_cmp(a, b):
    """Compare two RPM [epoch:]version-release strings like rpmvercmp/labelCompare."""
    ea, va, ra = _evr(a)
    eb, vb, rb = _evr(b)
    r = _rpmvercmp(ea, eb) or _rpmvercmp(va, vb)
    if r:
        return r
    if ra and rb:
        return _rpmvercmp(ra, rb)
    return 0


def compare(a, b, scheme):
    return deb_cmp(a, b) if scheme == "deb" else rpm_cmp(a, b)


def scheme_for(distro):
    return "deb" if distro in ("debian", "ubuntu") else "rpm"
