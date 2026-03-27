"""Tests for the persistent SQLite audit cache."""
import os
import time

import pytest
from unittest.mock import patch

# Use a temp directory for the cache database in tests
@pytest.fixture(autouse=True)
def temp_cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURE_PM_CACHE_DIR", str(tmp_path))

from talkdoc_secure_pm.auditor.cache import (
    cache_get,
    cache_put,
    cache_clear,
    cache_prune,
    cache_stats,
    _MAX_AGE_SECONDS,
)


class TestCacheBasicOps:
    def test_put_and_get_approved(self):
        cache_put("pkg:abc123", True, provider="grok", model="grok-4")
        result = cache_get("pkg:abc123")
        assert result is True

    def test_put_and_get_rejected(self):
        cache_put("evil:def456", False, provider="openai", model="gpt-5")
        result = cache_get("evil:def456")
        assert result is False

    def test_get_missing_key(self):
        result = cache_get("nonexistent:key")
        assert result is None

    def test_overwrite_entry(self):
        cache_put("pkg:abc", True)
        cache_put("pkg:abc", False)
        assert cache_get("pkg:abc") is False


class TestCacheExpiry:
    def test_expired_entry_returns_none(self, monkeypatch):
        cache_put("old:pkg", True)
        # Simulate time passing beyond MAX_AGE
        import talkdoc_secure_pm.auditor.cache as cache_mod
        original_time = time.time
        monkeypatch.setattr(time, "time", lambda: original_time() + _MAX_AGE_SECONDS + 1)
        assert cache_get("old:pkg") is None


class TestCacheClear:
    def test_clear_removes_all(self):
        cache_put("a:1", True)
        cache_put("b:2", False)
        count = cache_clear()
        assert count == 2
        assert cache_get("a:1") is None
        assert cache_get("b:2") is None


class TestCachePrune:
    def test_prune_removes_expired(self, monkeypatch):
        cache_put("old:1", True)
        # Monkey-patch time for the prune check
        import talkdoc_secure_pm.auditor.cache as cache_mod
        original_time = time.time
        monkeypatch.setattr(time, "time", lambda: original_time() + _MAX_AGE_SECONDS + 1)
        count = cache_prune()
        assert count >= 1


class TestCacheStats:
    def test_stats_counts(self):
        cache_put("a:1", True)
        cache_put("b:2", True)
        cache_put("c:3", False)
        stats = cache_stats()
        assert stats["total"] == 3
        assert stats["approved"] == 2
        assert stats["rejected"] == 1
        assert stats["oldest_timestamp"] is not None

    def test_empty_stats(self):
        stats = cache_stats()
        assert stats["total"] == 0
