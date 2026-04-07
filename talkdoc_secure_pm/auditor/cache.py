"""Persistent SQLite cache for AI audit results.

Stores audit verdicts keyed by ``{package_name}:{content_sha256}`` so that
repeated audits of the same package code (even across sessions) don't
require additional AI calls.

The database is stored at ``~/.cache/secure-pm/audit_cache.db`` by default
and can be overridden via the ``SECURE_PM_CACHE_DIR`` environment variable.
"""
import os
import sqlite3
import time
from pathlib import Path


_DEFAULT_CACHE_DIR = os.path.join(Path.home(), ".cache", "secure-pm")
_MAX_AGE_SECONDS = 30 * 24 * 3600  # 30 days


def _db_path() -> str:
    cache_dir = os.environ.get("SECURE_PM_CACHE_DIR", _DEFAULT_CACHE_DIR)
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, "audit_cache.db")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit_cache (
            cache_key  TEXT PRIMARY KEY,
            is_approved INTEGER NOT NULL,   -- 1 = approved, 0 = rejected
            provider   TEXT,
            model      TEXT,
            created_at REAL NOT NULL        -- Unix timestamp
        )"""
    )
    conn.commit()
    return conn


def cache_get(cache_key: str) -> bool | None:
    """Look up a cached audit result.  Returns ``True``/``False`` or
    ``None`` if no valid entry exists (missing or expired)."""
    try:
        conn = _get_connection()
        row = conn.execute(
            "SELECT is_approved, created_at FROM audit_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        conn.close()
        if row is None:
            return None
        is_approved, created_at = row
        if time.time() - created_at > _MAX_AGE_SECONDS:
            return None  # expired
        return bool(is_approved)
    except Exception:
        return None


def cache_put(cache_key: str, is_approved: bool, provider: str = "", model: str = "") -> None:
    """Store an audit result in the persistent cache."""
    try:
        conn = _get_connection()
        conn.execute(
            """INSERT OR REPLACE INTO audit_cache
               (cache_key, is_approved, provider, model, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (cache_key, int(is_approved), provider, model, time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # cache write failure is non-fatal


def cache_clear() -> int:
    """Delete all entries.  Returns the number of entries removed."""
    try:
        conn = _get_connection()
        cur = conn.execute("DELETE FROM audit_cache")
        count = cur.rowcount
        conn.commit()
        conn.close()
        return count
    except Exception:
        return 0


def cache_prune() -> int:
    """Remove expired entries (older than 30 days).  Returns count removed."""
    try:
        conn = _get_connection()
        cutoff = time.time() - _MAX_AGE_SECONDS
        cur = conn.execute("DELETE FROM audit_cache WHERE created_at < ?", (cutoff,))
        count = cur.rowcount
        conn.commit()
        conn.close()
        return count
    except Exception:
        return 0


def cache_stats() -> dict:
    """Return cache statistics: total entries, approved, rejected, oldest."""
    try:
        conn = _get_connection()
        total = conn.execute("SELECT COUNT(*) FROM audit_cache").fetchone()[0]
        approved = conn.execute("SELECT COUNT(*) FROM audit_cache WHERE is_approved = 1").fetchone()[0]
        rejected = conn.execute("SELECT COUNT(*) FROM audit_cache WHERE is_approved = 0").fetchone()[0]
        oldest_row = conn.execute("SELECT MIN(created_at) FROM audit_cache").fetchone()
        oldest = oldest_row[0] if oldest_row and oldest_row[0] else None
        conn.close()
        return {
            "total": total,
            "approved": approved,
            "rejected": rejected,
            "oldest_timestamp": oldest,
        }
    except Exception:
        return {"total": 0, "approved": 0, "rejected": 0, "oldest_timestamp": None}
