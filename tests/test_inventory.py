import json

from patchgap import inventory
from patchgap.runner import FakeRunner, Result

SAMPLE = """@@hostname
web-1
@@os-release
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
@@uname-r
6.8.0-100-generic
@@uname-v
#100-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan  1 00:00:00 UTC 2000
@@uname-m
x86_64
@@uid
0
@@pkgs-deb
openssh-server\t1:9.6p1-3ubuntu13.3\topenssh
linux-image-6.8.0-100-generic\t6.8.0-100.100\tlinux-signed
@@builtin
af_packet
@@loaded
algif_aead
nf_tables
@@kconfig
CONFIG_CRYPTO_USER_API_AEAD=m
@@checks
fake-nft no
fake-sshd yes
""".replace("\\t", "\t")


def test_parse_sample():
    inv = inventory.parse(SAMPLE)
    assert inv["host"] == "web-1"
    assert inv["os"] == {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "id_like": "debian",
                         "pretty": "Ubuntu 24.04.3 LTS"}
    assert inv["kernel"]["release"] == "6.8.0-100-generic"
    assert inv["root"] is True and inv["package_format"] == "deb"
    assert {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.3", "source": "openssh"} in inv["packages"]
    assert inv["loaded_modules"] == ["algif_aead", "nf_tables"]
    assert inv["kconfig"] == {"CONFIG_CRYPTO_USER_API_AEAD": "m"}
    assert inv["mitigation_checks"] == {"fake-nft": "no", "fake-sshd": "yes"}


def test_rpm_packages_strip_zero_epoch_and_srpm():
    text = "@@os-release\nID=rhel\nVERSION_ID=9.8\n@@uname-r\n5.14.0-1.el9.x86_64\n@@pkgs-rpm\n" \
           "kernel-core\t0:5.14.0-1.el9\tkernel-5.14.0-1.el9.src.rpm\nopenssh-server\t0:8.7p1-38.el9\topenssh-8.7p1-38.el9.src.rpm\n"
    inv = inventory.parse(text)
    assert inv["packages"][0] == {"name": "kernel-core", "version": "5.14.0-1.el9", "source": "kernel"}
    assert inv["packages"][1]["source"] == "openssh"


def test_script_contains_checks(feed):
    s = inventory.script(feed)
    assert "nft list table inet fake_table" in s
    assert "modprobe -n -v fakemod" in s
    assert "logingracetime 0" in s
    assert "sysctl -n net.fake.enabled" in s


def test_collect_local_uses_runner(feed):
    r = FakeRunner({("sh", "-c"): Result(0, SAMPLE)})
    inv = inventory.collect_local(feed, r)
    assert inv["os"]["codename"] == "noble"
    assert r.calls[0][:2] == ["sh", "-c"]


def test_collect_ssh_pipes_script(feed):
    seen = {}

    def answer(cmd, inp):
        seen["cmd"], seen["input"] = cmd, inp
        return Result(0, SAMPLE)
    inv = inventory.collect_ssh("admin@web-1", feed, FakeRunner({("ssh",): answer}))
    assert seen["cmd"][-3:] == ["admin@web-1", "sh", "-s"] and "BatchMode=yes" in seen["cmd"]
    assert "@@os-release" in seen["input"]
    assert inv["target"] == "admin@web-1"


def test_collect_ssh_failure(feed):
    import pytest
    with pytest.raises(RuntimeError, match="ssh failed"):
        inventory.collect_ssh("nope", feed, FakeRunner({("ssh",): Result(255, "", "Connection refused")}))


def test_load_list_and_single(tmp_path):
    inv = inventory.parse(SAMPLE)
    p1 = tmp_path / "one.json"
    p1.write_text(json.dumps(inv))
    p2 = tmp_path / "many.json"
    p2.write_text(json.dumps([inv, inv]))
    assert len(inventory.load(str(p1))) == 1 and len(inventory.load(str(p2))) == 2


def test_load_rejects_garbage(tmp_path):
    import pytest
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        inventory.load(str(p))


def test_real_script_is_valid_sh(feed):
    import shutil
    import subprocess
    sh = shutil.which("sh")
    r = subprocess.run([sh, "-n"], input=inventory.script(feed), text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
