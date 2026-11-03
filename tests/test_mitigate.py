import json
import os

import pytest

from patchgap import feed as feedmod
from patchgap.mitigate import MitigationError, Mitigator, State
from patchgap.runner import FakeRunner, Result


class FakeSystem(FakeRunner):
    """Simulates nft, modprobe, sshd, sysctl and systemctl against a temp root."""

    def __init__(self, root, builtin=False, nft_check_ok=True, sshd_ok=True):
        super().__init__()
        self.root, self.tables, self.sysctl = root, set(), {"net.fake.enabled": "1"}
        self.nft_check_ok, self.sshd_ok = nft_check_ok, sshd_ok

    def run(self, cmd, input=None, timeout=120):
        self.calls.append(list(cmd))
        if cmd[:2] == ["sh", "-c"]:
            return Result(0, "/usr/sbin/x")
        if cmd[0] == "nft":
            if cmd[1:3] == ["-c", "-f"]:
                return Result(0 if self.nft_check_ok else 1, "", "syntax error")
            if cmd[1] == "-f":
                self.tables.add("inet fake_table")
                return Result(0)
            if cmd[1:3] == ["list", "table"]:
                return Result(0 if " ".join(cmd[3:5]) in self.tables else 1)
            if cmd[1:3] == ["delete", "table"]:
                self.tables.discard(" ".join(cmd[3:5]))
                return Result(0)
        if cmd[0] == "modprobe":
            if cmd[1] == "-r":
                pm = os.path.join(self.root, "proc/modules")
                lines = [x for x in open(pm).read().splitlines() if not x.startswith(cmd[2] + " ")]
                open(pm, "w").write("\n".join(lines) + "\n")
                return Result(0)
            if cmd[1:3] == ["-n", "-v"]:
                d = os.path.join(self.root, "etc/modprobe.d")
                blocked = os.path.isdir(d) and any(
                    f"install {cmd[3]} /bin/false" in open(os.path.join(d, n)).read() for n in os.listdir(d))
                return Result(0, "install /bin/false\n" if blocked else "insmod /lib/x.ko\n")
        if cmd[0] == "sshd":
            dropin = os.path.join(self.root, "etc/ssh/sshd_config.d/00-patchgap-fake-sshd.conf")
            if cmd[1] == "-t":
                return Result(0 if self.sshd_ok else 255, "", "bad config")
            if cmd[1] == "-T":
                return Result(0, "port 22\nlogingracetime " + ("0" if os.path.exists(dropin) else "120") + "\n")
        if cmd[0] == "systemctl":
            return Result(0)
        if cmd[0] == "sysctl":
            if cmd[1] == "-n":
                return Result(0, self.sysctl.get(cmd[2], "") + "\n")
            if cmd[1] == "-w":
                k, v = cmd[2].split("=", 1)
                self.sysctl[k] = v
                return Result(0)
        return Result(1, "", f"unexpected {cmd}")


@pytest.fixture
def root(tmp_path):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/modules").write_text("fakemod 16384 0 - Live 0x0\nnf_tables 1 0 - Live 0x0\n")
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    (tmp_path / "etc/nftables.conf").write_text("#!/usr/sbin/nft -f\nflush ruleset\n")
    return tmp_path


def mk(root, **kw):
    sysm = FakeSystem(str(root), **kw)
    return Mitigator(sysm, root=str(root), state=State(str(root / "state.json")), kernel_release="6.0.0-test"), sysm


def test_plan_changes_nothing(root, feed):
    mit, sysm = mk(root)
    steps = mit.plan(feedmod.mitigation(feed, "fake-nft"), persist=True)
    assert any("nft -c -f" in s for s in steps) and any("nftables.conf" in s for s in steps)
    assert sysm.calls == [] and not (root / "etc/patchgap").exists()


def test_nft_apply_verify_revert(root, feed):
    mit, sysm = mk(root)
    m = feedmod.mitigation(feed, "fake-nft")
    assert mit.apply(m)["status"] == "applied"
    assert "inet fake_table" in sysm.tables
    assert (root / "etc/patchgap/fake-nft.nft").exists()
    st = json.loads((root / "state.json").read_text())
    assert st["applied"]["fake-nft"]["cves"] == ["CVE-0000-0001"]
    assert mit.apply(m)["status"] == "already-active"
    mit.revert(m)
    assert not sysm.tables and not (root / "etc/patchgap/fake-nft.nft").exists()
    assert "fake-nft" not in json.loads((root / "state.json").read_text())["applied"]


def test_nft_persist_adds_and_removes_include(root, feed):
    mit, _ = mk(root)
    m = feedmod.mitigation(feed, "fake-nft")
    mit.apply(m, persist=True)
    assert 'include "/etc/patchgap/fake-nft.nft"' in (root / "etc/nftables.conf").read_text()
    mit.revert(m)
    assert "patchgap" not in (root / "etc/nftables.conf").read_text()
    assert "flush ruleset" in (root / "etc/nftables.conf").read_text()


def test_nft_syntax_failure_rolls_back(root, feed):
    mit, sysm = mk(root, nft_check_ok=False)
    with pytest.raises(MitigationError, match="nft -c"):
        mit.apply(feedmod.mitigation(feed, "fake-nft"))
    assert not sysm.tables and not (root / "etc/patchgap/fake-nft.nft").exists()
    assert not (root / "state.json").exists()


def test_modprobe_apply_unloads_and_reverts(root, feed):
    mit, sysm = mk(root)
    m = feedmod.mitigation(feed, "fake-mod")
    mit.apply(m)
    assert ["modprobe", "-r", "fakemod"] in sysm.calls
    assert "install fakemod /bin/false" in (root / "etc/modprobe.d/patchgap-fake-mod.conf").read_text()
    mit.revert(m)
    assert not (root / "etc/modprobe.d/patchgap-fake-mod.conf").exists()


def test_modprobe_refuses_builtin(root, feed):
    (root / "lib/modules/6.0.0-test").mkdir(parents=True)
    (root / "lib/modules/6.0.0-test/modules.builtin").write_text("kernel/crypto/fakemod.ko\n")
    mit, _ = mk(root)
    with pytest.raises(MitigationError, match="built into"):
        mit.apply(feedmod.mitigation(feed, "fake-mod"))
    assert not (root / "etc/modprobe.d").exists()


def test_modprobe_refuses_builtin_by_kconfig(root, feed):
    (root / "boot").mkdir()
    (root / "boot/config-6.0.0-test").write_text("CONFIG_FAKEMOD=y\n")
    mit, _ = mk(root)
    with pytest.raises(MitigationError, match="CONFIG_FAKEMOD=y"):
        mit.apply(feedmod.mitigation(feed, "fake-mod"))


def test_sshd_dropin(root, feed):
    mit, sysm = mk(root)
    m = feedmod.mitigation(feed, "fake-sshd")
    mit.apply(m)
    assert (root / "etc/ssh/sshd_config.d/00-patchgap-fake-sshd.conf").read_text().endswith("LoginGraceTime 0\n")
    assert ["systemctl", "reload", "ssh"] in sysm.calls
    assert mit.verify(m)
    mit.revert(m)
    assert not mit.verify(m)


def test_sshd_requires_include(root, feed):
    (root / "etc/ssh/sshd_config").write_text("Port 22\n")
    mit, _ = mk(root)
    with pytest.raises(MitigationError, match="Include"):
        mit.apply(feedmod.mitigation(feed, "fake-sshd"))
    assert (root / "etc/ssh/sshd_config").read_text() == "Port 22\n"


def test_sshd_bad_config_removes_dropin(root, feed):
    mit, sysm = mk(root, sshd_ok=False)
    with pytest.raises(MitigationError, match="sshd -t"):
        mit.apply(feedmod.mitigation(feed, "fake-sshd"))
    assert not (root / "etc/ssh/sshd_config.d/00-patchgap-fake-sshd.conf").exists()
    assert not any(c[0] == "systemctl" for c in sysm.calls)


def test_sysctl_restores_previous(root, feed):
    mit, sysm = mk(root)
    m = feedmod.mitigation(feed, "fake-sysctl")
    mit.apply(m, persist=True)
    assert sysm.sysctl["net.fake.enabled"] == "0"
    assert (root / "etc/sysctl.d/99-patchgap-fake-sysctl.conf").exists()
    assert json.loads((root / "state.json").read_text())["applied"]["fake-sysctl"]["previous"] == {"net.fake.enabled": "1"}
    mit2 = Mitigator(sysm, root=str(root), state=State(str(root / "state.json")), kernel_release="6.0.0-test")
    mit2.revert(m)
    assert sysm.sysctl["net.fake.enabled"] == "1"
    assert not (root / "etc/sysctl.d/99-patchgap-fake-sysctl.conf").exists()


def test_missing_tool(root, feed):
    sysm = FakeSystem(str(root))
    orig = sysm.run
    sysm.run = lambda cmd, input=None, timeout=120: Result(1) if cmd[:2] == ["sh", "-c"] else orig(cmd, input)
    mit = Mitigator(sysm, root=str(root), state=State(str(root / "s.json")), kernel_release="x")
    with pytest.raises(MitigationError, match="not installed"):
        mit.apply(feedmod.mitigation(feed, "fake-nft"))


def test_bundled_mitigations_plan(tmp_path):
    f = feedmod.load(feedmod.BUNDLED)
    mit = Mitigator(FakeRunner(), root=str(tmp_path), state=State(str(tmp_path / "s.json")), kernel_release="x")
    for m in f["mitigations"]:
        assert mit.plan(m)
    nft = feedmod.mitigation(f, "cve-2026-98432-nft")
    assert "ip hdrlength > 5" in nft["ruleset"] and "priority -310" in nft["ruleset"]
    assert list(tmp_path.iterdir()) == []


def test_existing_external_block_is_left_alone(root, feed):
    (root / "etc/modprobe.d").mkdir(parents=True)
    (root / "etc/modprobe.d/distro.conf").write_text("install fakemod /bin/false\n")
    (root / "proc/modules").write_text("nf_tables 1 0 - Live 0x0\n")
    mit, sysm = mk(root)
    m = feedmod.mitigation(feed, "fake-mod")
    assert mit.apply(m)["status"] == "already-active-external"
    assert not (root / "etc/modprobe.d/patchgap-fake-mod.conf").exists()
    assert not (root / "state.json").exists()
