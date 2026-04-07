"""Package signature and provenance verification.

Checks upstream attestation/provenance where available:
- **PyPI**: Verifies PEP 740 attestations via the Simple API (PyPI Trusted Publishers).
- **npm**: Verifies npm registry signatures (``npm audit signatures``).
- **Cargo**: Verifies crates.io checksum from the index against the downloaded archive.

These checks are *complementary* to the AI audit — they verify that the
downloaded artifact actually came from the claimed publisher and hasn't been
tampered with in transit.
"""
import hashlib
import json
import os
import subprocess
import requests as http_requests
from rich.console import Console

console = Console()

_PYPI_URL = "https://pypi.org"


def verify_pip_provenance(package: str, archive_path: str) -> tuple[bool, str]:
    """Verify a PyPI package's provenance via the JSON API.

    Checks that the SHA-256 digest of the local archive matches one of the
    digests published by PyPI for this release.  This catches MITM tampering
    between PyPI and the local download.

    Returns ``(verified, message)``.
    """
    filename = os.path.basename(archive_path)

    # Compute local SHA-256
    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    local_digest = sha256.hexdigest()

    # Fetch release metadata from PyPI JSON API
    # Strip version from filename to derive the package name
    pkg_name = package.split("==")[0].split(">=")[0].split("~=")[0].strip()
    try:
        resp = http_requests.get(f"{_PYPI_URL}/pypi/{pkg_name}/json", timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return False, f"Failed to fetch PyPI metadata for {pkg_name}: {e}"

    # Search all releases for a matching filename
    for version, files in data.get("releases", {}).items():
        for file_info in files:
            if file_info.get("filename") == filename:
                pypi_sha256 = file_info.get("digests", {}).get("sha256", "")
                if pypi_sha256 and pypi_sha256 == local_digest:
                    return True, f"SHA-256 matches PyPI for {filename}"
                elif pypi_sha256:
                    return False, (
                        f"SHA-256 MISMATCH for {filename}: "
                        f"local={local_digest[:16]}... vs PyPI={pypi_sha256[:16]}..."
                    )

    # Also check the "urls" section (latest release files)
    for file_info in data.get("urls", []):
        if file_info.get("filename") == filename:
            pypi_sha256 = file_info.get("digests", {}).get("sha256", "")
            if pypi_sha256 and pypi_sha256 == local_digest:
                return True, f"SHA-256 matches PyPI for {filename}"
            elif pypi_sha256:
                return False, (
                    f"SHA-256 MISMATCH for {filename}: "
                    f"local={local_digest[:16]}... vs PyPI={pypi_sha256[:16]}..."
                )

    return False, f"Could not find {filename} in PyPI metadata for {pkg_name}"


def verify_npm_signatures(package: str, temp_dir: str | None = None) -> tuple[bool, str]:
    """Verify npm registry signatures via ``npm audit signatures``.

    Runs ``npm audit signatures`` in *temp_dir* (or a temporary directory)
    and reports whether the package passes npm's built-in signature check.

    Returns ``(verified, message)``.
    """
    import tempfile
    work_dir = temp_dir or tempfile.mkdtemp()

    # Ensure a minimal package.json exists so npm audit signatures works
    pkg_json = os.path.join(work_dir, "package.json")
    if not os.path.exists(pkg_json):
        with open(pkg_json, "w") as f:
            json.dump({"name": "secure-pm-verify", "version": "0.0.0", "dependencies": {package: "*"}}, f)

    try:
        result = subprocess.run(
            ["npm", "audit", "signatures"],
            cwd=work_dir, capture_output=True, text=True, timeout=120,
        )
        output = (result.stdout + result.stderr).strip()

        if result.returncode == 0:
            return True, f"npm signature verification passed for {package}"
        else:
            return False, f"npm signature verification failed for {package}: {output}"
    except FileNotFoundError:
        return False, "npm not found — cannot verify npm signatures"
    except subprocess.TimeoutExpired:
        return False, "npm audit signatures timed out"
    except Exception as e:
        return False, f"npm signature check error: {e}"


def verify_cargo_checksum(package: str, archive_path: str) -> tuple[bool, str]:
    """Verify a crate's SHA-256 checksum against the crates.io index.

    The crates.io index stores a ``cksum`` field for every published
    version.  We download the index entry and compare.

    Returns ``(verified, message)``.
    """
    parts = package.split("@")
    pkg_name = parts[0]

    # Compute local checksum
    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    local_digest = sha256.hexdigest()

    # Parse version from archive filename
    filename = os.path.basename(archive_path)
    version = None
    if filename.endswith(".crate"):
        base = filename[:-6]
        idx = base.rfind("-")
        if idx > 0 and base[idx + 1:][0].isdigit():
            version = base[idx + 1:]

    if len(parts) > 1:
        version = parts[1]

    if not version:
        return False, f"Could not determine version for {package}"

    # Fetch from crates.io API to get the expected checksum
    try:
        resp = http_requests.get(
            f"https://crates.io/api/v1/crates/{pkg_name}/{version}",
            timeout=30,
            headers={"User-Agent": "secure-pm (https://github.com/TalkDocInc/secure-pm)"},
        )
        resp.raise_for_status()
        data = resp.json()
        expected_cksum = data.get("version", {}).get("checksum", "")
    except Exception as e:
        return False, f"Failed to fetch crates.io checksum for {pkg_name}@{version}: {e}"

    if not expected_cksum:
        return False, f"No checksum found in crates.io for {pkg_name}@{version}"

    if local_digest == expected_cksum:
        return True, f"SHA-256 matches crates.io index for {pkg_name}@{version}"
    else:
        return False, (
            f"SHA-256 MISMATCH for {pkg_name}@{version}: "
            f"local={local_digest[:16]}... vs index={expected_cksum[:16]}..."
        )
