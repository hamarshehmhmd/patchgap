import json
import os

import pytest

from patchgap import cli
from patchgap.runner import Result
from test_inventory import SAMPLE
from test_mitigate import FakeSystem

FEED = os.path.join(os.path.dirname(__file__), "fixtures", "feed.yaml")


def local(sample=SAMPLE):
    class R(FakeSystem):
        def run(self, cmd, input=None, timeout=120):
            if cmd[:2] == ["sh", "-c"] and "@@os-release" in cmd[2]:
                return Result(0, sample)
            return super().run(cmd, input, timeout)
    return R


@pytest.fixture
def root(tmp_path):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/modules").write_text("")
    (tmp_path / "etc/ssh").mkdir(parents=True)
    (tmp_path / "etc/ssh/sshd_config").write_text("Include /etc/ssh/sshd_config.d/*.conf\n")
    return tmp_path


def run(args, runner, capsys):
    code = cli.main(["--feed", FEED] + args, runner=runner)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_check_local_human(root, capsys):
    code, out, _ = run(["--root", str(root), "check"], local()(str(root)), capsys)
    assert code == 1
    assert "CVE-0000-0001" in out and "fix-pending" in out and "exit 1" in out


def test_check_json(root, capsys):
    code, out, _ = run(["--root", str(root), "check", "--json"], local()(str(root)), capsys)
    d = json.loads(out)
    assert d["exit_code"] == 1 == code
    res = {r["cve"]: r for r in d["hosts"][0]["results"]}
    assert res["CVE-0000-0001"]["state"] == "fix-pending"
    assert res["CVE-0000-0002"]["state"] == "fixed" or res["CVE-0000-0002"]["state"] == "fix-available"
    assert res["CVE-0000-0003"]["state"] == "no-fix"


def test_check_inventory_files(tmp_path, capsys):
    from patchgap import inventory
    inv = inventory.parse(SAMPLE.replace("fake-nft no", "fake-nft yes").replace("@@checks\n", "@@checks\nfake-mod yes\n"))
    p = tmp_path / "fleet.json"
    p.write_text(json.dumps([inv]))
    code, out, _ = run(["check", "-i", str(p), "--json"], None, capsys)
    d = json.loads(out)
    assert code == 2 and d["summary"]


def test_check_bad_ssh_gives_3(capsys):
    from patchgap.runner import FakeRunner
    code, _, err = run(["check", "--ssh", "ghost"], FakeRunner({("ssh",): Result(255, "", "no route")}), capsys)
    assert code == 3 and "ghost" in err


def test_mitigate_dry_run_default(root, capsys):
    r = local()(str(root))
    code, out, _ = run(["--root", str(root), "mitigate", "CVE-0000-0001"], r, capsys)
    assert code == 0 and "dry run" in out and "nft -c -f" in out
    assert not r.tables and not (root / "etc/patchgap").exists()


def test_mitigate_apply_then_status_then_cleanup(root, capsys):
    r = local()(str(root))
    code, out, _ = run(["--root", str(root), "mitigate", "CVE-0000-0001", "--apply"], r, capsys)
    assert code == 0 and "verified active" in out and r.tables
    # still exposed -> cleanup keeps it
    code, out, _ = run(["--root", str(root), "cleanup", "--apply"], r, capsys)
    assert "keep" in out and r.tables
    # now pretend we rebooted into the fixed kernel
    fixed = SAMPLE.replace("6.8.0-100-generic", "6.8.0-200-generic").replace("#100-Ubuntu", "#200-Ubuntu")
    r2 = local(fixed)(str(root))
    r2.tables = r.tables
    code, out, _ = run(["--root", str(root), "cleanup"], r2, capsys)
    assert "dry run" in out and r2.tables
    code, out, _ = run(["--root", str(root), "cleanup", "--apply"], r2, capsys)
    assert "reverted fake-nft" in out and not r2.tables
    state = json.loads((root / "var/lib/patchgap/state.json").read_text())
    assert state["applied"] == {} and [h["action"] for h in state["history"]] == ["apply", "revert"]


def test_cleanup_waits_for_reboot(root, capsys):
    r = local()(str(root))
    run(["--root", str(root), "mitigate", "CVE-0000-0001", "--apply"], r, capsys)
    pending = SAMPLE.replace("linux-image-6.8.0-100-generic\t6.8.0-100.100",
                             "linux-image-6.8.0-200-generic\t6.8.0-200.200")
    r2 = local(pending)(str(root))
    r2.tables = r.tables
    code, out, _ = run(["--root", str(root), "cleanup", "--apply"], r2, capsys)
    assert "reboot" in out and r2.tables


def test_mitigate_not_exposed(root, capsys):
    s = SAMPLE.replace("noble", "trusty").replace("6.8.0-100-generic", "3.13.0-170-generic")
    code, out, _ = run(["--root", str(root), "mitigate", "CVE-0000-0001"], local(s)(str(root)), capsys)
    assert code == 0 and "nothing to do" in out


def test_revert_dry_and_apply(root, capsys):
    r = local()(str(root))
    run(["--root", str(root), "mitigate", "CVE-0000-0001", "--apply"], r, capsys)
    code, out, _ = run(["--root", str(root), "revert", "fake-nft"], r, capsys)
    assert "dry run" in out and r.tables
    code, out, _ = run(["--root", str(root), "revert", "CVE-0000-0001", "--apply"], r, capsys)
    assert "reverted" in out and not r.tables


def test_apply_on_real_root_needs_root(monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_root", lambda: False)
    with pytest.raises(SystemExit, match="run as root"):
        cli.main(["--feed", FEED, "mitigate", "CVE-0000-0001", "--apply"], runner=local()("/nonexistent"))


def test_unknown_cve(capsys):
    with pytest.raises(SystemExit, match="not in the feed"):
        cli.main(["--feed", FEED, "mitigate", "CVE-1999-0000"], runner=None)


def test_list_and_inventory(root, tmp_path, capsys):
    code, out, _ = run(["list"], None, capsys)
    assert "CVE-0000-0002" in out and "fake-sshd" in out
    o = tmp_path / "inv.json"
    code, _, _ = run(["inventory", "-o", str(o)], local()(str(root)), capsys)
    assert code == 0 and json.loads(o.read_text())["host"] == "web-1"


def test_feed_update_bad_url_keeps_feed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: 9\n")
    code, _, err = run(["feed", "update", "--url", str(bad)], None, capsys)
    assert code == 3 and "keeping current feed" in err
    code, out, _ = run(["feed", "update", "--url", FEED], None, capsys)
    assert code == 0 and (tmp_path / "patchgap/feed.yaml").exists()


def test_status_shows_mitigations(root, capsys):
    code, out, _ = run(["--root", str(root), "status"], local()(str(root)), capsys)
    assert code == 1 and "mitigation fake-nft: active=no" in out and "source:" in out
