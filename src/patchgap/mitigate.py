"""Apply, verify and revert interim mitigations.

Safety model:
  * Nothing changes unless the caller passes apply=True (the CLI defaults to a dry run).
  * Every file patchgap writes lives in a patchgap-named path and is recorded in the state
    file, so revert removes exactly what apply added.
  * Each kind validates before it changes anything live (nft -c, sshd -t, builtin check)
    and rolls back its own files if the live step fails.
  * All paths are relative to `root` and all commands go through a Runner, so tests run
    against a temp dir and a fake runner."""
import datetime as dt
import json
import os
import re
import shutil


class MitigationError(RuntimeError):
    pass


def _now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


class State:
    def __init__(self, path):
        self.path = path
        self.data = {"applied": {}, "history": []}
        if os.path.exists(path):
            with open(path) as fh:
                self.data = json.load(fh)
            self.data.setdefault("applied", {})
            self.data.setdefault("history", [])

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def record(self, mid, info):
        self.data["applied"][mid] = info
        self.data["history"].append({"at": info["applied_at"], "action": "apply", "id": mid})
        self.save()

    def forget(self, mid):
        self.data["applied"].pop(mid, None)
        self.data["history"].append({"at": _now(), "action": "revert", "id": mid})
        self.save()


class Step:
    def __init__(self, desc, fn=None):
        self.desc, self.fn = desc, fn


class Mitigator:
    def __init__(self, runner, root="/", state=None, kernel_release=None):
        self.runner = runner
        self.root = root
        self.state = state or State(self.path("/var/lib/patchgap/state.json"))
        self.kernel_release = kernel_release or os.uname().release

    # ---------- helpers ----------
    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def exists(self, p):
        return os.path.exists(self.path(p))

    def read(self, p):
        try:
            with open(self.path(p)) as fh:
                return fh.read()
        except OSError:
            return ""

    def write(self, p, text, mode=0o644):
        full = self.path(p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)
        os.chmod(full, mode)

    def remove(self, p):
        try:
            os.remove(self.path(p))
        except FileNotFoundError:
            pass

    def run(self, cmd, check=True, input=None):
        r = self.runner.run(cmd, input=input)
        if check and not r.ok:
            raise MitigationError(f"`{' '.join(cmd)}` failed (rc {r.rc}): {(r.err or r.out).strip()[:400]}")
        return r

    def have(self, tool):
        return self.runner.run(["sh", "-c", f"command -v {tool}"]).ok

    # ---------- public API ----------
    def plan(self, m, persist=False):
        return [s.desc for s in getattr(self, "_" + m["kind"])(m, persist)["apply"]]

    def apply(self, m, persist=False):
        if m["id"] in self.state.data["applied"]:
            if self.verify(m):
                return {"id": m["id"], "status": "already-active"}
        ops = getattr(self, "_" + m["kind"])(m, persist)
        for tool in m.get("requires", []):
            if not self.have(tool):
                raise MitigationError(f"{m['id']}: '{tool}' is not installed")
        for pre in ops.get("precheck", []):
            pre.fn()
        done = []
        try:
            for s in ops["apply"]:
                s.fn()
                done.append(s)
        except Exception:
            for s in reversed(ops.get("rollback", [])):
                try:
                    s.fn()
                except Exception:  # noqa: BLE001
                    pass
            raise
        if not self.verify(m):
            for s in ops["revert"]:
                try:
                    s.fn()
                except Exception:  # noqa: BLE001
                    pass
            raise MitigationError(f"{m['id']}: applied but verification failed; rolled back")
        self.state.record(m["id"], {"applied_at": _now(), "cves": m["cves"], "kind": m["kind"],
                                    "persist": persist, "files": ops.get("files", []),
                                    "previous": ops.get("previous", {})})
        return {"id": m["id"], "status": "applied"}

    def revert_plan(self, m):
        info = self.state.data["applied"].get(m["id"], {})
        return [s.desc for s in getattr(self, "_" + m["kind"])(m, info.get("persist", False), info)["revert"]]

    def revert(self, m):
        info = self.state.data["applied"].get(m["id"])
        ops = getattr(self, "_" + m["kind"])(m, (info or {}).get("persist", False), info or {})
        for s in ops["revert"]:
            s.fn()
        self.state.forget(m["id"])
        return {"id": m["id"], "status": "reverted"}

    def verify(self, m):
        return getattr(self, "_verify_" + m["kind"])(m)

    # ---------- nftables ----------
    def _nftables(self, m, persist, info=None):
        fam, name = m["table"]["family"], m["table"]["name"]
        f = f"/etc/patchgap/{m['id']}.nft"
        inc = f'include "{f}"'
        conf = "/etc/nftables.conf"

        def write_rules():
            self.write(f, "# Added by patchgap for " + ", ".join(m["cves"]) + ". Remove with: patchgap revert "
                       + m["id"] + " --apply\n" + m["ruleset"])

        def add_include():
            text = self.read(conf)
            if not text:
                raise MitigationError(f"--persist: {conf} not found; use your distro's firewall service instead")
            if inc not in text:
                self.write(conf, text.rstrip("\n") + "\n" + inc + "  # patchgap\n", 0o755)

        def drop_include():
            text = self.read(conf)
            if inc in text:
                self.write(conf, "".join(line for line in text.splitlines(True) if inc not in line), 0o755)

        def delete_table():
            if self.runner.run(["nft", "list", "table", fam, name]).ok:
                self.run(["nft", "delete", "table", fam, name])

        apply = [Step(f"write {f}", write_rules),
                 Step(f"nft -c -f {f}   (syntax check, no change)", lambda: self.run(["nft", "-c", "-f", self.path(f)])),
                 Step(f"nft -f {f}   (load table {fam} {name})", lambda: self.run(["nft", "-f", self.path(f)]))]
        if persist:
            apply.append(Step(f"append '{inc}' to {conf}", add_include))
        revert = [Step(f"nft delete table {fam} {name}", delete_table)]
        if persist or (info or {}).get("persist"):
            revert.append(Step(f"remove include line from {conf}", drop_include))
        revert.append(Step(f"remove {f}", lambda: self.remove(f)))
        return {"apply": apply, "revert": revert, "files": [f],
                "rollback": [Step("delete table", delete_table), Step("drop include", drop_include),
                             Step("remove file", lambda: self.remove(f))]}

    def _verify_nftables(self, m):
        t = m["table"]
        return self.runner.run(["nft", "list", "table", t["family"], t["name"]]).ok

    # ---------- modprobe ----------
    def _builtin(self, mod):
        rel = self.kernel_release
        if re.search(rf"/{re.escape(mod)}\.ko", self.read(f"/lib/modules/{rel}/modules.builtin")):
            return True
        return False

    def _modprobe(self, m, persist, info=None):
        f = f"/etc/modprobe.d/patchgap-{m['id']}.conf"
        body = "# Added by patchgap for " + ", ".join(m["cves"]) + "\n" + "".join(
            f"install {mod} /bin/false\n" for mod in m["modules"])

        def precheck():
            for mod in m["modules"]:
                if self._builtin(mod):
                    raise MitigationError(f"{mod} is built into kernel {self.kernel_release}; blocking the module "
                                          "cannot work here. Update the kernel instead.")
            kcfg = m.get("kconfig")
            if kcfg and re.search(rf"^{re.escape(kcfg)}=y$", self.read(f"/boot/config-{self.kernel_release}"), re.M):
                raise MitigationError(f"{kcfg}=y in /boot/config-{self.kernel_release}: built in, cannot block.")

        def unload():
            loaded = self.read("/proc/modules")
            for mod in m["modules"]:
                if re.search(rf"^{re.escape(mod)} ", loaded, re.M):
                    self.run(["modprobe", "-r", mod])

        apply = [Step(f"write {f}: " + "; ".join(f"install {x} /bin/false" for x in m["modules"]),
                      lambda: self.write(f, body)),
                 Step("unload " + ", ".join(m["modules"]) + " if loaded (modprobe -r)", unload)]
        revert = [Step(f"remove {f} (module can load again; nothing is reloaded)", lambda: self.remove(f))]
        return {"apply": apply, "revert": revert, "files": [f], "precheck": [Step("builtin check", precheck)],
                "rollback": [Step("remove file", lambda: self.remove(f))]}

    def _verify_modprobe(self, m):
        loaded = self.read("/proc/modules")
        for mod in m["modules"]:
            r = self.runner.run(["modprobe", "-n", "-v", mod])
            if "/bin/false" not in (r.out + r.err) or re.search(rf"^{re.escape(mod)} ", loaded, re.M):
                return False
        return True

    # ---------- sshd ----------
    def _sshd(self, m, persist, info=None):
        f = f"/etc/ssh/sshd_config.d/00-patchgap-{m['id']}.conf"
        body = "# Added by patchgap for " + ", ".join(m["cves"]) + "\n" + "".join(
            f"{k} {v}\n" for k, v in m["directives"].items())

        def precheck():
            main = self.read("/etc/ssh/sshd_config")
            if not re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf", main, re.M | re.I):
                raise MitigationError("/etc/ssh/sshd_config has no 'Include /etc/ssh/sshd_config.d/*.conf'; "
                                      "patchgap will not edit sshd_config itself. Add the directive by hand.")

        def test_config():
            r = self.runner.run(["sshd", "-t"])
            if not r.ok:
                self.remove(f)
                raise MitigationError(f"sshd -t rejected the config, drop-in removed: {r.err.strip()[:300]}")

        def reload():
            for unit in ("ssh", "sshd"):
                if self.runner.run(["systemctl", "reload", unit]).ok:
                    return
            raise MitigationError("could not reload ssh or sshd via systemctl")

        apply = [Step(f"write {f}: " + "; ".join(f"{k} {v}" for k, v in m["directives"].items()),
                      lambda: self.write(f, body)),
                 Step("sshd -t   (config test; drop-in removed if it fails)", test_config),
                 Step("systemctl reload ssh (or sshd)", reload)]
        revert = [Step(f"remove {f}", lambda: self.remove(f)),
                  Step("sshd -t", lambda: self.run(["sshd", "-t"])),
                  Step("systemctl reload ssh (or sshd)", reload)]
        return {"apply": apply, "revert": revert, "files": [f], "precheck": [Step("Include check", precheck)],
                "rollback": [Step("remove file", lambda: self.remove(f))]}

    def _verify_sshd(self, m):
        r = self.runner.run(["sshd", "-T"])
        lines = {line.strip().lower() for line in r.out.splitlines()}
        return r.ok and all(f"{k.lower()} {str(v).lower()}" in lines for k, v in m["directives"].items())

    # ---------- sysctl ----------
    def _sysctl(self, m, persist, info=None):
        f = f"/etc/sysctl.d/99-patchgap-{m['id']}.conf"
        prev = dict((info or {}).get("previous", {}))
        out = {"previous": prev}

        def capture():
            for k in m["settings"]:
                prev[k] = self.run(["sysctl", "-n", k]).out.strip()

        def set_all():
            for k, v in m["settings"].items():
                self.run(["sysctl", "-w", f"{k}={v}"])

        def restore():
            for k, v in prev.items():
                if v != "":
                    self.run(["sysctl", "-w", f"{k}={v}"])

        apply = [Step("record current values", capture),
                 Step("sysctl -w " + " ".join(f"{k}={v}" for k, v in m["settings"].items()), set_all)]
        if persist:
            apply.append(Step(f"write {f}", lambda: self.write(
                f, "".join(f"{k} = {v}\n" for k, v in m["settings"].items()))))
        revert = [Step("restore previous values " + (" ".join(f"{k}={v}" for k, v in prev.items()) or ""), restore),
                  Step(f"remove {f}", lambda: self.remove(f))]
        out.update(apply=apply, revert=revert, files=[f] if persist else [],
                   rollback=[Step("restore", restore), Step("remove", lambda: self.remove(f))])
        return out

    def _verify_sysctl(self, m):
        return all(self.runner.run(["sysctl", "-n", k]).out.strip() == str(v) for k, v in m["settings"].items())


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def which(tool):
    return shutil.which(tool)
