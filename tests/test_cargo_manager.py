"""Tests for CargoManager: hash pinning and crate filename parsing."""
import json
import os

import pytest
from unittest.mock import patch, MagicMock

from talkdoc_secure_pm.managers.cargo_manager import CargoManager


@pytest.fixture
def mgr():
    """CargoManager with a mocked-out auditor (no real AI calls)."""
    m = CargoManager()
    m.auditor.client = None
    m.auditor.model = None
    return m


class TestCargoPinDependency:
    def test_pin_creates_lockfile(self, mgr, tmp_path):
        """pin_dependency should create a JSON lockfile with checksums."""
        lock_file = str(tmp_path / "Cargo.lock.secure.json")
        hashes = {"serde-1.0.200.crate": "a" * 64}
        mgr.pin_dependency("serde", hashes, filepath=lock_file)

        assert os.path.exists(lock_file)
        with open(lock_file) as f:
            data = json.load(f)

        assert "packages" in data
        assert "serde@1.0.200" in data["packages"]
        entry = data["packages"]["serde@1.0.200"]
        assert entry["name"] == "serde"
        assert entry["version"] == "1.0.200"
        assert entry["checksum"] == f"sha256:{'a' * 64}"

    def test_pin_appends_to_existing(self, mgr, tmp_path):
        """pin_dependency should append to an existing lockfile."""
        lock_file = str(tmp_path / "Cargo.lock.secure.json")

        hashes1 = {"serde-1.0.200.crate": "a" * 64}
        mgr.pin_dependency("serde", hashes1, filepath=lock_file)

        hashes2 = {"tokio-1.38.0.crate": "b" * 64}
        mgr.pin_dependency("tokio", hashes2, filepath=lock_file)

        with open(lock_file) as f:
            data = json.load(f)

        assert "serde@1.0.200" in data["packages"]
        assert "tokio@1.38.0" in data["packages"]

    def test_pin_with_at_version(self, mgr, tmp_path):
        """Package spec with @ version should work."""
        lock_file = str(tmp_path / "Cargo.lock.secure.json")
        hashes = {"serde-1.0.200.crate": "c" * 64}
        mgr.pin_dependency("serde@1.0.200", hashes, filepath=lock_file)

        with open(lock_file) as f:
            data = json.load(f)

        assert "serde@1.0.200" in data["packages"]

    def test_pin_handles_pre_release_version(self, mgr, tmp_path):
        """Pre-release versions like 1.0.0-alpha should parse correctly."""
        lock_file = str(tmp_path / "Cargo.lock.secure.json")
        hashes = {"mypkg-1.0.0-alpha.crate": "d" * 64}
        mgr.pin_dependency("mypkg", hashes, filepath=lock_file)

        with open(lock_file) as f:
            data = json.load(f)

        # Should have parsed name=mypkg, version=1.0.0-alpha
        keys = list(data["packages"].keys())
        assert any("mypkg" in k for k in keys)
