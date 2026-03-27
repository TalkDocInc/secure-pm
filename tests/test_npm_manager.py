"""Tests for NpmManager: hash pinning."""
import json
import os

import pytest
from unittest.mock import patch, MagicMock

from talkdoc_secure_pm.managers.npm_manager import NpmManager


@pytest.fixture
def mgr():
    """NpmManager with a mocked-out auditor (no real AI calls)."""
    m = NpmManager()
    m.auditor.client = None
    m.auditor.model = None
    return m


class TestNpmPinDependency:
    def test_pin_creates_lockfile(self, mgr, tmp_path):
        """pin_dependency should create a JSON lockfile with integrity hashes."""
        lock_file = str(tmp_path / "package-lock.secure.json")
        hashes = {"express-4.18.0.tgz": "abc123def456" * 4}  # 48-char hex
        mgr.pin_dependency("express", hashes, filepath=lock_file)

        assert os.path.exists(lock_file)
        with open(lock_file) as f:
            data = json.load(f)

        assert "packages" in data
        assert "express" in data["packages"]
        entry = data["packages"]["express"]
        assert entry["version"] == "4.18.0"
        assert entry["integrity"].startswith("sha256-")

    def test_pin_appends_to_existing(self, mgr, tmp_path):
        """pin_dependency should append to an existing lockfile."""
        lock_file = str(tmp_path / "package-lock.secure.json")

        # First pin
        hashes1 = {"express-4.18.0.tgz": "a" * 64}
        mgr.pin_dependency("express", hashes1, filepath=lock_file)

        # Second pin
        hashes2 = {"lodash-4.17.21.tgz": "b" * 64}
        mgr.pin_dependency("lodash", hashes2, filepath=lock_file)

        with open(lock_file) as f:
            data = json.load(f)

        assert "express" in data["packages"]
        assert "lodash" in data["packages"]

    def test_pin_integrity_format(self, mgr, tmp_path):
        """Integrity hash should be base64-encoded SHA-256."""
        lock_file = str(tmp_path / "package-lock.secure.json")
        # Known SHA-256 hex: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        # (empty string SHA-256)
        hashes = {"pkg-1.0.0.tgz": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        mgr.pin_dependency("pkg", hashes, filepath=lock_file)

        with open(lock_file) as f:
            data = json.load(f)

        integrity = data["packages"]["pkg"]["integrity"]
        assert integrity.startswith("sha256-")
        # Verify it's valid base64
        import base64
        b64_part = integrity[len("sha256-"):]
        decoded = base64.b64decode(b64_part)
        assert len(decoded) == 32  # SHA-256 = 32 bytes
