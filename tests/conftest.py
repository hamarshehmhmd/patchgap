import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from patchgap import feed as feedmod  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def feed():
    return feedmod.load(os.path.join(FIX, "feed.yaml"))


def make_inv(distro, rel, krel, kver="", packages=(), fmt=None, checks=None, version_id=""):
    return {"host": "test-host", "os": {"id": distro, "codename": rel if distro in ("debian", "ubuntu") else "",
                                       "version_id": version_id or rel, "pretty": f"{distro} {rel}"},
            "kernel": {"release": krel, "version": kver, "machine": "x86_64"},
            "package_format": fmt or ("deb" if distro in ("debian", "ubuntu") else "rpm"),
            "packages": [{"name": n, "version": v, "source": s} for n, v, s in packages],
            "builtin_modules": [], "loaded_modules": [], "kconfig": {},
            "mitigation_checks": checks or {}}


@pytest.fixture
def inv():
    return make_inv
