"""Safe archive extraction with path traversal and zip bomb protection."""
import os
import tarfile
import zipfile

# Maximum total extracted size (500 MB) and single file size (100 MB)
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_FILES = 50_000


def _is_within(path: str, parent: str) -> bool:
    """Return True only if resolved *path* is inside *parent*."""
    return os.path.realpath(path).startswith(os.path.realpath(parent) + os.sep)


def safe_extract_tar(archive_path: str, dest_dir: str) -> None:
    """Extract a tar/tar.gz/crate archive with path traversal and zip bomb guards."""
    total_bytes = 0
    file_count = 0
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            # Block path traversal: absolute paths, ".." components, and symlink escapes
            if member.name.startswith("/") or ".." in member.name.split(os.sep):
                raise ValueError(f"Blocked path traversal in tar member: {member.name}")
            target = os.path.join(dest_dir, member.name)
            if not _is_within(target, dest_dir):
                raise ValueError(f"Blocked path traversal (resolved) in tar member: {member.name}")
            # Symlink escape check
            if member.issym() or member.islnk():
                link_target = os.path.normpath(os.path.join(os.path.dirname(target), member.linkname))
                if not _is_within(link_target, dest_dir):
                    raise ValueError(f"Blocked symlink escape in tar member: {member.name} -> {member.linkname}")
            # Size guards
            if member.isfile():
                if member.size > MAX_FILE_BYTES:
                    raise ValueError(f"File too large in archive: {member.name} ({member.size} bytes)")
                total_bytes += member.size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(f"Archive exceeds maximum total extraction size ({MAX_TOTAL_BYTES} bytes)")
            file_count += 1
            if file_count > MAX_FILES:
                raise ValueError(f"Archive contains too many files (>{MAX_FILES})")

        # Use data filter if available (Python 3.12+), otherwise manual extraction
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest_dir, filter="data")
        else:
            tar.extractall(dest_dir)


def safe_extract_zip(archive_path: str, dest_dir: str) -> None:
    """Extract a zip/whl archive with path traversal and zip bomb guards."""
    total_bytes = 0
    file_count = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            # Block path traversal
            if info.filename.startswith("/") or ".." in info.filename.split(os.sep):
                raise ValueError(f"Blocked path traversal in zip member: {info.filename}")
            target = os.path.join(dest_dir, info.filename)
            if not _is_within(target, dest_dir):
                raise ValueError(f"Blocked path traversal (resolved) in zip member: {info.filename}")
            # Size guards (file_size is the uncompressed size)
            if not info.is_dir():
                if info.file_size > MAX_FILE_BYTES:
                    raise ValueError(f"File too large in archive: {info.filename} ({info.file_size} bytes)")
                total_bytes += info.file_size
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(f"Archive exceeds maximum total extraction size ({MAX_TOTAL_BYTES} bytes)")
            file_count += 1
            if file_count > MAX_FILES:
                raise ValueError(f"Archive contains too many files (>{MAX_FILES})")

        zf.extractall(dest_dir)
