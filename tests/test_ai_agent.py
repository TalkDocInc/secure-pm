"""Tests for the AI auditor: content-based cache, fail-closed mode."""
import os

import pytest

# Patch out the OpenAI import so tests don't need an API key or real client
from unittest.mock import patch

# Must patch env BEFORE importing AIAuditor so the constructor doesn't try to
# connect to a real provider.
with patch.dict(os.environ, {"AI_PROVIDER": "grok"}, clear=False):
    from talkdoc_secure_pm.auditor.ai_agent import AIAuditor


@pytest.fixture
def auditor():
    """AIAuditor with no API key configured (fail-closed mode)."""
    with patch.dict(os.environ, {"AI_PROVIDER": "grok", "XAI_API_KEY": ""}, clear=False):
        a = AIAuditor()
        # Force no-client mode
        a.client = None
        a.model = None
    return a


@pytest.fixture
def tmp_pkg(tmp_path):
    """Helper: create a fake extracted package directory with given files."""
    def _create(files: dict[str, str]):
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return str(tmp_path)
    return _create


# ---------------------------------------------------------------------------
# Content-based cache tests
# ---------------------------------------------------------------------------

class TestCacheContentBased:
    def test_same_content_same_result(self, auditor, tmp_pkg):
        """Two calls with identical file content → second is a cache hit."""
        extract_dir = tmp_pkg({"setup.py": "print('hello')"})
        r1 = auditor.audit_package_source("testpkg", extract_dir)
        r2 = auditor.audit_package_source("testpkg", extract_dir)
        assert r1 == r2
        # Cache should have exactly 1 entry
        assert len(auditor._cache) == 1

    def test_different_content_different_key(self, auditor, tmp_path):
        """Two versions with different content produce separate cache entries."""
        # Version A
        dir_a = tmp_path / "a"
        dir_a.mkdir()
        (dir_a / "setup.py").write_text("version_a = 1")
        auditor.audit_package_source("pkg", str(dir_a))

        # Version B
        dir_b = tmp_path / "b"
        dir_b.mkdir()
        (dir_b / "setup.py").write_text("version_b = 2")
        auditor.audit_package_source("pkg", str(dir_b))

        assert len(auditor._cache) == 2


# ---------------------------------------------------------------------------
# Fail-closed mode tests (no API key = REJECT)
# ---------------------------------------------------------------------------

class TestFailClosedMode:
    def test_no_client_rejects_package(self, auditor, tmp_pkg):
        """When no AI client is configured, audit returns False (fail-closed)."""
        extract_dir = tmp_pkg({"setup.py": "setup(name='ok')"})
        result = auditor.audit_package_source("fakepkg", extract_dir)
        assert result is False

    def test_cache_stores_rejection(self, auditor, tmp_pkg):
        """Fail-closed rejection is cached."""
        extract_dir = tmp_pkg({"setup.py": "setup(name='ok')"})
        auditor.audit_package_source("pkg", extract_dir)
        assert len(auditor._cache) == 1
        # The cached value should be False
        assert list(auditor._cache.values())[0] is False


# ---------------------------------------------------------------------------
# SHA-256 cache key test
# ---------------------------------------------------------------------------

class TestCacheUsesSHA256:
    def test_cache_key_uses_sha256(self, auditor, tmp_pkg):
        """Cache keys should use SHA-256 hashes (64 hex chars), not MD5 (32 hex chars)."""
        extract_dir = tmp_pkg({"setup.py": "print('test')"})
        auditor.audit_package_source("testpkg", extract_dir)
        key = list(auditor._cache.keys())[0]
        # Format: "testpkg:{sha256_hex}"
        hash_part = key.split(":")[1]
        assert len(hash_part) == 64  # SHA-256 = 64 hex chars (MD5 = 32)
