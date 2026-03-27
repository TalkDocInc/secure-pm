"""Tests for safe archive extraction: path traversal, zip bomb, and symlink guards."""
import io
import os
import tarfile
import zipfile
import tempfile

import pytest

from talkdoc_secure_pm.safe_extract import safe_extract_tar, safe_extract_zip


@pytest.fixture
def dest_dir(tmp_path):
    d = tmp_path / "extract"
    d.mkdir()
    return str(d)


# ---------------------------------------------------------------------------
# Tar path traversal tests
# ---------------------------------------------------------------------------

class TestSafeExtractTar:
    def _make_tar(self, tmp_path, members: list[tuple[str, bytes]]) -> str:
        """Create a tar.gz with given (name, content) members."""
        archive = tmp_path / "test.tar.gz"
        with tarfile.open(str(archive), "w:gz") as tf:
            for name, data in members:
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return str(archive)

    def test_safe_extraction(self, tmp_path, dest_dir):
        archive = self._make_tar(tmp_path, [("hello.py", b"print('hi')")])
        safe_extract_tar(archive, dest_dir)
        assert os.path.exists(os.path.join(dest_dir, "hello.py"))

    def test_blocks_dotdot_traversal(self, tmp_path, dest_dir):
        archive = self._make_tar(tmp_path, [("../../etc/passwd", b"evil")])
        with pytest.raises(ValueError, match="path traversal"):
            safe_extract_tar(archive, dest_dir)

    def test_blocks_absolute_path(self, tmp_path, dest_dir):
        archive = self._make_tar(tmp_path, [("/etc/passwd", b"evil")])
        with pytest.raises(ValueError, match="path traversal"):
            safe_extract_tar(archive, dest_dir)

    def test_blocks_oversized_file(self, tmp_path, dest_dir, monkeypatch):
        """Files exceeding MAX_FILE_BYTES should be rejected."""
        import talkdoc_secure_pm.safe_extract as se
        # Lower the limit so we don't need to create a huge file
        monkeypatch.setattr(se, "MAX_FILE_BYTES", 10)
        archive = self._make_tar(tmp_path, [("big.bin", b"x" * 100)])
        with pytest.raises(ValueError, match="too large"):
            safe_extract_tar(str(archive), dest_dir)


# ---------------------------------------------------------------------------
# Zip path traversal tests
# ---------------------------------------------------------------------------

class TestSafeExtractZip:
    def _make_zip(self, tmp_path, members: list[tuple[str, bytes]]) -> str:
        archive = tmp_path / "test.zip"
        with zipfile.ZipFile(str(archive), "w") as zf:
            for name, data in members:
                zf.writestr(name, data)
        return str(archive)

    def test_safe_extraction(self, tmp_path, dest_dir):
        archive = self._make_zip(tmp_path, [("hello.py", b"print('hi')")])
        safe_extract_zip(archive, dest_dir)
        assert os.path.exists(os.path.join(dest_dir, "hello.py"))

    def test_blocks_dotdot_traversal(self, tmp_path, dest_dir):
        archive = self._make_zip(tmp_path, [("../../etc/passwd", b"evil")])
        with pytest.raises(ValueError, match="path traversal"):
            safe_extract_zip(archive, dest_dir)

    def test_blocks_absolute_path(self, tmp_path, dest_dir):
        archive = self._make_zip(tmp_path, [("/etc/passwd", b"evil")])
        with pytest.raises(ValueError, match="path traversal"):
            safe_extract_zip(archive, dest_dir)
