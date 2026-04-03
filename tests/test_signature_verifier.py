"""Tests for package signature / provenance verification."""
import hashlib

from unittest.mock import patch, MagicMock

from talkdoc_secure_pm.signature_verifier import (
    verify_pip_provenance,
    verify_npm_signatures,
    verify_cargo_checksum,
)


class TestVerifyPipProvenance:
    def test_matching_hash_passes(self, tmp_path):
        """When local SHA-256 matches PyPI metadata, verification passes."""
        # Create a fake archive
        archive = tmp_path / "requests-2.33.0-py3-none-any.whl"
        archive.write_bytes(b"fake archive content")
        local_hash = hashlib.sha256(b"fake archive content").hexdigest()

        # Mock PyPI response
        pypi_response = {
            "releases": {
                "2.33.0": [
                    {
                        "filename": "requests-2.33.0-py3-none-any.whl",
                        "digests": {"sha256": local_hash},
                    }
                ]
            },
            "urls": [],
        }

        with patch("talkdoc_secure_pm.signature_verifier.http_requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = pypi_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            verified, msg = verify_pip_provenance("requests", str(archive))
            assert verified is True
            assert "matches PyPI" in msg

    def test_mismatching_hash_fails(self, tmp_path):
        """When local SHA-256 doesn't match PyPI, verification fails."""
        archive = tmp_path / "requests-2.33.0-py3-none-any.whl"
        archive.write_bytes(b"tampered content")

        pypi_response = {
            "releases": {
                "2.33.0": [
                    {
                        "filename": "requests-2.33.0-py3-none-any.whl",
                        "digests": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
                    }
                ]
            },
            "urls": [],
        }

        with patch("talkdoc_secure_pm.signature_verifier.http_requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = pypi_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            verified, msg = verify_pip_provenance("requests", str(archive))
            assert verified is False
            assert "MISMATCH" in msg

    def test_missing_file_in_pypi(self, tmp_path):
        """When the filename isn't found in PyPI metadata."""
        archive = tmp_path / "unknown-1.0.0.whl"
        archive.write_bytes(b"data")

        pypi_response = {"releases": {}, "urls": []}

        with patch("talkdoc_secure_pm.signature_verifier.http_requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = pypi_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            verified, msg = verify_pip_provenance("unknown", str(archive))
            assert verified is False
            assert "Could not find" in msg


class TestVerifyNpmSignatures:
    def test_npm_not_found(self):
        """When npm is not installed, should return failure gracefully."""
        with patch("talkdoc_secure_pm.signature_verifier.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("npm not found")
            verified, msg = verify_npm_signatures("express")
            assert verified is False
            assert "npm not found" in msg

    def test_npm_success(self, tmp_path):
        """When npm audit signatures succeeds."""
        with patch("talkdoc_secure_pm.signature_verifier.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="All signatures verified", stderr="")
            verified, msg = verify_npm_signatures("express", temp_dir=str(tmp_path))
            assert verified is True


class TestVerifyCargoChecksum:
    def test_matching_checksum_passes(self, tmp_path):
        """When local checksum matches crates.io, verification passes."""
        archive = tmp_path / "serde-1.0.200.crate"
        archive.write_bytes(b"crate content")
        local_hash = hashlib.sha256(b"crate content").hexdigest()

        crates_response = {
            "version": {"checksum": local_hash}
        }

        with patch("talkdoc_secure_pm.signature_verifier.http_requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = crates_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            verified, msg = verify_cargo_checksum("serde@1.0.200", str(archive))
            assert verified is True
            assert "matches crates.io" in msg

    def test_mismatching_checksum_fails(self, tmp_path):
        """When local checksum doesn't match crates.io, verification fails."""
        archive = tmp_path / "serde-1.0.200.crate"
        archive.write_bytes(b"tampered crate")

        crates_response = {
            "version": {"checksum": "0" * 64}
        }

        with patch("talkdoc_secure_pm.signature_verifier.http_requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = crates_response
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            verified, msg = verify_cargo_checksum("serde@1.0.200", str(archive))
            assert verified is False
            assert "MISMATCH" in msg
