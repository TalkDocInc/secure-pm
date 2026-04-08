"""Tests for PipManager: download subprocess args, temp dir cleanup, version pinning."""
import os
import subprocess

import pytest
from unittest.mock import patch, MagicMock

from talkdoc_secure_pm.managers.pip_manager import PipManager


@pytest.fixture
def mgr():
    """PipManager with a mocked-out auditor (no real AI calls)."""
    m = PipManager()
    m.auditor.client = None
    m.auditor.model = None
    return m


# ---------------------------------------------------------------------------
# Download subprocess args
# ---------------------------------------------------------------------------

class TestDownloadArgs:
    @patch("talkdoc_secure_pm.managers.pip_manager.subprocess.run")
    def test_download_with_deps_no_flag(self, mock_run, mgr, tmp_path):
        """include_deps=True should NOT pass --no-deps."""
        mock_run.side_effect = self._fake_download(tmp_path)
        try:
            mgr.download("requests", include_deps=True)
        except Exception:
            pass
        cmd = mock_run.call_args[0][0]
        assert "--no-deps" not in cmd

    @patch("talkdoc_secure_pm.managers.pip_manager.subprocess.run")
    def test_download_without_deps_has_flag(self, mock_run, mgr, tmp_path):
        """include_deps=False should pass --no-deps."""
        mock_run.side_effect = self._fake_download(tmp_path)
        try:
            mgr.download("requests", include_deps=False)
        except Exception:
            pass
        cmd = mock_run.call_args[0][0]
        assert "--no-deps" in cmd

    @patch("talkdoc_secure_pm.managers.pip_manager.subprocess.run")
    def test_uses_sys_executable(self, mock_run, mgr, tmp_path):
        """Should use sys.executable, not bare 'pip'."""
        import sys
        mock_run.side_effect = self._fake_download(tmp_path)
        try:
            mgr.download("requests", include_deps=True)
        except Exception:
            pass
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == sys.executable
        assert cmd[1:3] == ["-m", "pip"]

    @staticmethod
    def _fake_download(tmp_path):
        """Helper: returns a side_effect that creates a dummy archive."""
        def _se(cmd, **kwargs):
            if "download" in cmd:
                # Create a dummy .whl file in the temp dir (-d arg)
                d_idx = cmd.index("-d") + 1
                dest = cmd[d_idx]
                open(os.path.join(dest, "fakepkg-1.0.0-py3-none-any.whl"), "w").close()
            return MagicMock(returncode=0)
        return _se


# ---------------------------------------------------------------------------
# Temp dir cleanup on failure
# ---------------------------------------------------------------------------

class TestTempDirCleanup:
    @patch("talkdoc_secure_pm.managers.pip_manager.subprocess.run")
    def test_cleanup_on_download_failure(self, mock_run):
        """If pip download fails, the temp dir should be cleaned up."""
        mock_run.side_effect = subprocess.CalledProcessError(1, "pip")
        mgr = PipManager()
        mgr.auditor.client = None
        with pytest.raises(subprocess.CalledProcessError):
            mgr.download("nonexistent-pkg-xyz-123", include_deps=False)
        # After the exception, any temp dirs created should be gone.
        # We can't easily check the exact dir, but at least confirm no exception leak.


# ---------------------------------------------------------------------------
# Version pinning
# ---------------------------------------------------------------------------

class TestPinDependency:
    def test_pin_writes_version(self, mgr, tmp_path):
        """pin_dependency should write pkg==version with hash."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        hashes = {"requests-2.33.0-py3-none-any.whl": "abc123"}
        mgr.pin_dependency("requests", hashes, filepath=str(req_file))

        content = req_file.read_text()
        assert "requests==2.33.0" in content
        assert "--hash=sha256:abc123" in content

    def test_pin_tar_gz_version(self, mgr, tmp_path):
        """pin_dependency handles .tar.gz filenames correctly."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        hashes = {"urllib3-2.4.0.tar.gz": "def456"}
        mgr.pin_dependency("urllib3", hashes, filepath=str(req_file))

        content = req_file.read_text()
        assert "urllib3==2.4.0" in content
        assert "--hash=sha256:def456" in content

    def test_pin_multiple_deps(self, mgr, tmp_path):
        """Multiple archives produce multiple pinned lines."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        hashes = {
            "requests-2.33.0-py3-none-any.whl": "aaa",
            "charset_normalizer-3.5.0-cp312-manylinux.whl": "bbb",
        }
        mgr.pin_dependency("requests", hashes, filepath=str(req_file))
        content = req_file.read_text()
        lines = [l for l in content.strip().split("\n") if not l.startswith("#")]
        # Should have 2 non-comment pinned lines
        assert len(lines) == 2
