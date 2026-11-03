from patchgap import feed as feedmod, match


def one(feed, inv, cid="CVE-0000-0001"):
    return match.assess(feedmod.cve(feed, cid), inv)


def test_debian_vulnerable_then_fixed(feed, inv):
    r = one(feed, inv("debian", "bookworm", "6.1.0-40-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.190-1 (2026-10-01)"))
    assert r["state"] == match.FIX_AVAILABLE and r["fixed_version"] == "6.1.200-1"
    r = one(feed, inv("debian", "bookworm", "6.1.0-41-amd64", "#1 SMP PREEMPT_DYNAMIC Debian 6.1.200-1 (2026-10-16)"))
    assert r["state"] == match.FIXED


def test_debian_picks_backport_series(feed, inv):
    r = one(feed, inv("debian", "bookworm", "6.12.0-0.deb12.9-amd64", "#1 SMP Debian 6.12.100-1~deb12u1"))
    assert r["package"] == "linux-6.12" and r["state"] == match.FIX_AVAILABLE


def test_debian_reboot_required(feed, inv):
    i = inv("debian", "bookworm", "6.1.0-40-amd64", "#1 SMP Debian 6.1.190-1",
            packages=[("linux-image-6.1.0-41-amd64", "6.1.200-1", "linux")])
    r = one(feed, i)
    assert r["state"] == match.REBOOT and r["state"] in match.EXPOSED


def test_ubuntu_pending_in_proposed(feed, inv):
    r = one(feed, inv("ubuntu", "noble", "6.8.0-100-generic", "#100-Ubuntu SMP PREEMPT_DYNAMIC"))
    assert r["running"] == "6.8.0-100.100"
    assert r["state"] == match.FIX_PENDING and "proposed" in r["reason"]


def test_ubuntu_installed_from_proposed(feed, inv):
    r = one(feed, inv("ubuntu", "noble", "6.8.0-200-generic", "#200-Ubuntu SMP"))
    assert r["state"] == match.FIXED and "proposed" in r["reason"]


def test_ubuntu_hwe_kernel_on_jammy(feed, inv):
    r = one(feed, inv("ubuntu", "jammy", "6.8.0-150-generic", "#150~22.04.1-Ubuntu SMP"))
    assert r["package"] == "linux-hwe-6.8" and r["running"] == "6.8.0-150.150~22.04.1"
    assert r["state"] == match.FIX_PENDING
    r = one(feed, inv("ubuntu", "jammy", "5.15.0-100-generic", "#110-Ubuntu SMP"))
    assert r["package"] == "linux"


def test_ubuntu_cloud_flavour(feed, inv):
    r = one(feed, inv("ubuntu", "noble", "6.8.0-1050-aws", "#55-Ubuntu SMP"))
    assert r["package"] == "linux-aws" and r["state"] == match.FIX_AVAILABLE
    r = one(feed, inv("ubuntu", "noble", "6.8.0-1100-aws", "#100-Ubuntu SMP"))
    assert r["state"] == match.FIXED


def test_ubuntu_no_fix_and_not_affected(feed, inv):
    assert one(feed, inv("ubuntu", "focal", "5.4.0-200-generic", "#220-Ubuntu SMP"))["state"] == match.NO_FIX
    assert one(feed, inv("ubuntu", "trusty", "3.13.0-170-generic", "#220-Ubuntu SMP"))["state"] == match.NOT_AFFECTED


def test_unknown_distro_is_not_guessed(feed, inv):
    r = one(feed, inv("rocky", "9", "5.14.0-600.el9.x86_64"))
    assert r["state"] == match.UNKNOWN and "no data" in r["reason"]


def test_rhel(feed, inv):
    assert one(feed, inv("rhel", "9", "5.14.0-687.64.1.el9_8.x86_64", version_id="9.8"))["state"] == match.FIX_AVAILABLE
    assert one(feed, inv("rhel", "9", "5.14.0-700.1.1.el9_8.x86_64", version_id="9.8"))["state"] == match.FIXED
    assert one(feed, inv("rhel", "7", "3.10.0-1160.el7.x86_64", version_id="7.9"))["state"] == match.NOT_AFFECTED


def test_rhel_reboot_required(feed, inv):
    i = inv("rhel", "9", "5.14.0-687.64.1.el9_8.x86_64", version_id="9.8",
            packages=[("kernel-core", "5.14.0-687.64.1.el9_8", "kernel"), ("kernel-core", "5.14.0-700.1.1.el9_8", "kernel")])
    assert one(feed, i)["state"] == match.REBOOT


def test_amazon_series(feed, inv):
    r = one(feed, inv("amzn", "2023", "6.12.100-1.1.amzn2023.x86_64", version_id="2023"))
    assert r["package"] == "kernel6.12" and r["state"] == match.FIX_AVAILABLE
    r = one(feed, inv("amzn", "2023", "6.1.200-300.400.amzn2023.aarch64", version_id="2023"))
    assert r["package"] == "kernel" and r["state"] == match.FIXED


def test_package_component(feed, inv):
    i = inv("debian", "bookworm", "6.1.0-41-amd64", "Debian 6.1.200-1",
            packages=[("openssh-server", "1:9.2p1-2+deb12u3", "openssh")])
    assert one(feed, i, "CVE-0000-0002")["state"] == match.FIX_AVAILABLE
    i["packages"][0]["version"] = "1:9.2p1-2+deb12u9"
    assert one(feed, i, "CVE-0000-0002")["state"] == match.FIXED
    i["packages"] = []
    assert one(feed, i, "CVE-0000-0002")["state"] == match.NOT_INSTALLED


def test_rpm_package_component(feed, inv):
    i = inv("rhel", "9", "5.14.0-700.1.1.el9_8.x86_64", version_id="9.8",
            packages=[("openssh-server", "8.7p1-38.el9", "openssh")])
    assert one(feed, i, "CVE-0000-0002")["state"] == match.FIX_AVAILABLE


def test_report_and_exit_codes(feed, inv):
    vuln = inv("ubuntu", "noble", "6.8.0-100-generic", "#100-Ubuntu SMP")
    rep = match.report(feed, vuln, only=["CVE-0000-0001"])
    assert match.exit_code([rep]) == 1
    vuln["mitigation_checks"] = {"fake-nft": "yes"}
    rep = match.report(feed, vuln, only=["CVE-0000-0001"])
    assert rep["results"][0]["mitigated"] and match.exit_code([rep]) == 2
    ok = inv("ubuntu", "trusty", "3.13.0-170-generic", "#220-Ubuntu SMP")
    assert match.exit_code([match.report(feed, ok, only=["CVE-0000-0001"])]) == 0


def test_running_kernel_version_parsing(inv):
    assert match.running_kernel_version(inv("ubuntu", "noble", "6.8.0-149-generic", "#149-Ubuntu SMP")) == "6.8.0-149.149"
    assert match.running_kernel_version(inv("debian", "trixie", "6.12.48+deb13-amd64",
                                            "#1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-16)")) == "6.12.113-1"
    assert match.running_kernel_version(inv("amzn", "2", "5.10.271-272.1121.amzn2.x86_64")) == "5.10.271-272.1121.amzn2"
    assert match.running_kernel_version(inv("debian", "sid", "6.0-custom", "#1 SMP")) is None


def test_custom_kernel_is_unknown(feed, inv):
    r = one(feed, inv("debian", "bookworm", "6.12.94+", "#1 SMP PREEMPT_DYNAMIC Mon Oct 19 19:23:48 UTC 2026"))
    assert r["state"] == match.UNKNOWN and "custom" in r["reason"]
