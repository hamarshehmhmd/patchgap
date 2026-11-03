"""patchgap command line."""
import argparse
import json
import os
import sys

from . import __version__, feed as feedmod, inventory, match
from .mitigate import Mitigator, MitigationError, State, is_root
from .runner import Runner

COLORS = {"fixed": "32", "not-affected": "32", "not-installed": "32", "reboot-required": "33",
          "fix-available": "31", "fix-pending": "31", "no-fix": "31", "unknown": "35"}


def c(text, code, on):
    return f"\033[{code}m{text}\033[0m" if on else text


def _feed(args):
    try:
        return feedmod.load(args.feed)
    except (OSError, feedmod.FeedError) as e:
        sys.exit(f"patchgap: {e}")


def _state(args):
    root = args.root or "/"
    return State(args.state or os.path.join(root, "var/lib/patchgap/state.json"))


def gather(args, feed, runner):
    invs, errors = [], []
    for path in args.inventory or []:
        try:
            invs.extend(inventory.load(path))
        except (OSError, ValueError) as e:
            errors.append(str(e))
    hosts = list(args.ssh or [])
    if args.hosts:
        with open(args.hosts) as fh:
            hosts += [h.strip() for h in fh if h.strip() and not h.startswith("#")]
    for h in hosts:
        try:
            invs.append(inventory.collect_ssh(h, feed, runner))
        except RuntimeError as e:
            errors.append(str(e))
    if not invs and not errors:
        invs.append(inventory.collect_local(feed, runner))
    return invs, errors


def print_report(rep, color, verbose=False):
    print(c(f"{rep['host']}", "1", color) + f"  {rep['os']}  kernel {rep['kernel']}")
    for r in rep["results"]:
        name = f"{r['cve']}" + (f" ({r['name']})" if r.get("name") else "")
        st = r["state"]
        tag = st
        if r["exposed"]:
            tag += " + MITIGATED" if r["mitigated"] else ""
        print(f"  {name:<34} {c(tag, COLORS.get(st, '0'), color):<28} {r.get('reason', '')}")
        if r["exposed"] or verbose:
            for m in r["mitigations"]:
                rec = ", recorded" if m["recorded"] else ""
                print(f"      mitigation {m['id']}: active={m['active']}{rec}")
            if r.get("source"):
                print(f"      source: {r['source']}")


def summarize(reports):
    counts = {}
    for rep in reports:
        for r in rep["results"]:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
    return counts


def cmd_check(args, runner):
    feed = _feed(args)
    invs, errors = gather(args, feed, runner)
    state = _state(args).data if not (args.inventory or args.ssh or args.hosts) else None
    reports = [match.report(feed, inv, state, args.cve) for inv in invs]
    code = match.exit_code(reports)
    if getattr(args, "strict", False) and code == 0 and any(
            r["state"] == match.UNKNOWN for rep in reports for r in rep["results"]):
        code = 1
    if errors and code == 0:
        code = 3
    if args.json:
        print(json.dumps({"patchgap": __version__, "feed": feed["_path"], "feed_generated": feed.get("generated"),
                          "exit_code": code, "summary": summarize(reports), "hosts": reports,
                          "errors": errors}, indent=2))
    else:
        color = bool(os.environ.get("FORCE_COLOR")) or (sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
        for rep in reports:
            print_report(rep, color, args.verbose)
            print()
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        s = summarize(reports)
        print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(s.items())) +
              f"   (feed generated {feed.get('generated')})")
        hint = {1: "exposed hosts without an active mitigation - see `patchgap mitigate <CVE>`",
                2: "exposed, but every exposure has an active mitigation; keep patching",
                0: "nothing exposed", 3: "some hosts could not be checked"}[code]
        print(f"exit {code}: {hint}")
    return code


def cmd_inventory(args, runner):
    feed = _feed(args)
    invs, errors = gather(args, feed, runner)
    out = invs[0] if len(invs) == 1 else invs
    text = json.dumps(out, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text + "\n")
        print(f"wrote {args.output} ({len(invs)} host(s))", file=sys.stderr)
    else:
        print(text)
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    return 3 if errors else 0


def _local_report(args, feed, runner, only=None):
    inv = inventory.collect_local(feed, runner)
    return inv, match.report(feed, inv, _state(args).data, only)


def _mitigator(args, runner, inv=None):
    rel = (inv or {}).get("kernel", {}).get("release") if inv else None
    return Mitigator(runner, root=args.root or "/", state=_state(args), kernel_release=rel)


def _need_root(args):
    if args.apply and (args.root in (None, "/")) and not is_root():
        sys.exit("patchgap: --apply changes the system; run as root (or use --root DIR for a test tree)")


def cmd_mitigate(args, runner):
    feed = _feed(args)
    cve = feedmod.cve(feed, args.cve)
    if not cve:
        sys.exit(f"patchgap: {args.cve} is not in the feed (see `patchgap list`)")
    if not cve.get("mitigations"):
        print(f"{cve['id']}: the feed has no vetted mitigation. Patch, or isolate the host.")
        return 1
    _need_root(args)
    inv, rep = _local_report(args, feed, runner, [cve["id"]])
    r = rep["results"][0]
    print(f"{cve['id']}: {r['state']} - {r.get('reason', '')}")
    if not r["exposed"] and not args.force:
        print("not exposed on this host; nothing to do (use --force to apply anyway)")
        return 0
    mit = _mitigator(args, runner, inv)
    code = 0
    for mid in cve["mitigations"]:
        m = feedmod.mitigation(feed, mid)
        print(f"\nmitigation {mid} ({m['kind']}): {m['summary']}")
        print(f"  breaks: {m['breaks'].strip()}")
        print(f"  limits: {m['limits'].strip()}")
        for s in m["sources"]:
            print(f"  source: {s}")
        if not args.apply:
            print("  plan (dry run - nothing changed; re-run with --apply):")
            for step in mit.plan(m, args.persist):
                print(f"    - {step}")
            continue
        try:
            res = mit.apply(m, args.persist)
            print(f"  {res['status']}; verified active")
        except MitigationError as e:
            print(f"  FAILED: {e}", file=sys.stderr)
            code = 3
    return code


def _mits_for(feed, target):
    m = feedmod.mitigation(feed, target)
    if m:
        return [m]
    cve = feedmod.cve(feed, target)
    if cve:
        return [feedmod.mitigation(feed, x) for x in cve.get("mitigations", [])]
    sys.exit(f"patchgap: no mitigation or CVE called {target}")


def cmd_revert(args, runner):
    feed = _feed(args)
    _need_root(args)
    mit = _mitigator(args, runner)
    for m in _mits_for(feed, args.target):
        if not args.apply:
            print(f"{m['id']}: plan (dry run; re-run with --apply):")
            for step in mit.revert_plan(m):
                print(f"  - {step}")
            continue
        try:
            print(f"{m['id']}: {mit.revert(m)['status']}")
        except MitigationError as e:
            print(f"{m['id']}: FAILED: {e}", file=sys.stderr)
            return 3
    return 0


def cmd_cleanup(args, runner):
    """Revert mitigations whose CVEs are now fixed in the *running* system."""
    feed = _feed(args)
    _need_root(args)
    state = _state(args)
    applied = dict(state.data["applied"])
    if not applied:
        print("no mitigations recorded in " + state.path)
        return 0
    inv, rep = _local_report(args, feed, runner)
    by_cve = {r["cve"]: r for r in rep["results"]}
    mit = Mitigator(runner, root=args.root or "/", state=state, kernel_release=inv["kernel"]["release"])
    still = 0
    for mid, info in applied.items():
        m = feedmod.mitigation(feed, mid)
        states = {cid: by_cve.get(cid, {}).get("state", "unknown") for cid in info["cves"]}
        done = all(s in (match.FIXED, match.NOT_AFFECTED, match.NOT_INSTALLED) for s in states.values())
        desc = ", ".join(f"{k}={v}" for k, v in states.items())
        if not done or m is None:
            still += 1
            why = " - reboot into the fixed kernel first" if match.REBOOT in states.values() else ""
            print(f"keep   {mid}: {desc}{why}")
            continue
        if not args.apply:
            print(f"revert {mid}: {desc} (dry run; re-run with --apply)")
            for step in mit.revert_plan(m):
                print(f"         - {step}")
            continue
        try:
            mit.revert(m)
            print(f"reverted {mid}: {desc}")
        except MitigationError as e:
            print(f"FAILED {mid}: {e}", file=sys.stderr)
            return 3
    return 0


def cmd_list(args, runner):
    feed = _feed(args)
    if args.json:
        print(json.dumps({k: v for k, v in feed.items() if k != "_path"}, indent=2, default=str))
        return 0
    print(f"feed: {feed['_path']} (generated {feed.get('generated')})")
    for cv in feed["cves"]:
        sev = cv.get("severity", {})
        print(f"\n{cv['id']}" + (f" ({cv['name']})" if cv.get("name") else "") +
              f"  published {cv.get('published')}  cvss {sev.get('cvss3', '?')}")
        print("  " + " ".join(cv["summary"].split()))
        counts = {}
        for f in cv["fixes"]:
            counts.setdefault(f["distro"], {}).setdefault(f["status"], 0)
            counts[f["distro"]][f["status"]] += 1
        for d, s in counts.items():
            print(f"  {d:<7} " + ", ".join(f"{k} {v}" for k, v in sorted(s.items())))
        print("  mitigations: " + (", ".join(cv.get("mitigations") or []) or "none"))
    return 0


def cmd_feed(args, runner):
    if args.feed_cmd == "path":
        print(feedmod.load(args.feed)["_path"])
        return 0
    try:
        dest, f = feedmod.update(args.url)
    except (OSError, feedmod.FeedError) as e:
        print(f"patchgap: feed update failed, keeping current feed: {e}", file=sys.stderr)
        return 3
    print(f"updated {dest}: {len(f['cves'])} CVEs, generated {f.get('generated')}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="patchgap", description="Find hosts exposed to hot Linux CVEs while your "
                                "distro's fix lags, apply reversible stopgaps, and remove them once patched.")
    p.add_argument("--version", action="version", version=f"patchgap {__version__}")
    p.add_argument("--feed", help="feed YAML (default: cached update, else bundled)")
    p.add_argument("--root", help="filesystem root for mitigations and state (testing)")
    p.add_argument("--state", help="state file (default ROOT/var/lib/patchgap/state.json)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def targets(sp):
        sp.add_argument("--inventory", "-i", action="append", help="inventory JSON from `patchgap inventory`")
        sp.add_argument("--ssh", action="append", metavar="HOST", help="collect from HOST over ssh (repeatable)")
        sp.add_argument("--hosts", metavar="FILE", help="file with one ssh host per line")

    sp = sub.add_parser("check", help="exposure report (local, inventory files or ssh hosts)")
    targets(sp)
    sp.add_argument("--cve", action="append", help="only this CVE (repeatable)")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.add_argument("--strict", action="store_true", help="treat 'unknown' as exposed (exit 1)")
    sp.set_defaults(fn=cmd_check)

    sp = sub.add_parser("status", help="this host: exposure plus mitigation state")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_check, inventory=None, ssh=None, hosts=None, cve=None, verbose=True, strict=False)

    sp = sub.add_parser("inventory", help="print inventory JSON for this host or ssh hosts")
    targets(sp)
    sp.add_argument("-o", "--output")
    sp.set_defaults(fn=cmd_inventory)

    sp = sub.add_parser("mitigate", help="apply the vetted stopgap for a CVE (dry run unless --apply)")
    sp.add_argument("cve")
    sp.add_argument("--apply", action="store_true", help="actually change the system")
    sp.add_argument("--persist", action="store_true", help="also survive reboot where supported")
    sp.add_argument("--force", action="store_true", help="apply even if this host is not exposed")
    sp.set_defaults(fn=cmd_mitigate)

    sp = sub.add_parser("revert", help="remove a mitigation (by mitigation id or CVE)")
    sp.add_argument("target")
    sp.add_argument("--apply", action="store_true")
    sp.set_defaults(fn=cmd_revert)

    sp = sub.add_parser("cleanup", help="revert mitigations whose CVEs are fixed in the running system")
    sp.add_argument("--apply", action="store_true")
    sp.set_defaults(fn=cmd_cleanup)

    sp = sub.add_parser("list", help="CVEs and mitigations in the feed")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("feed", help="feed path / update")
    fs = sp.add_subparsers(dest="feed_cmd", required=True)
    fs.add_parser("path")
    u = fs.add_parser("update")
    u.add_argument("--url", default=feedmod.DEFAULT_URL, help="feed URL or local file")
    sp.set_defaults(fn=cmd_feed)
    return p


def main(argv=None, runner=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args, runner or Runner())
    except RuntimeError as e:
        print(f"patchgap: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
