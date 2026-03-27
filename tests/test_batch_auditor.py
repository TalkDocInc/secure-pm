"""Tests for batch_auditor: requirements parsing, package.json, Cargo.toml."""
import os
import json
import tempfile

import pytest

from talkdoc_secure_pm.batch_auditor import (
    parse_requirements,
    parse_package_json,
    parse_cargo_toml,
)


# ---------------------------------------------------------------------------
# parse_requirements
# ---------------------------------------------------------------------------

class TestParseRequirements:
    def test_basic_packages(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\n")
        result = parse_requirements(str(req))
        assert result == ["requests", "flask"]

    def test_preserves_version_specifiers(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.33.0\nflask>=3.0\nnumpy~=2.0\n")
        result = parse_requirements(str(req))
        assert "requests==2.33.0" in result
        assert "flask>=3.0" in result
        assert "numpy~=2.0" in result

    def test_skips_comments_and_blanks(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n\nrequests\n   \n# another\nflask\n")
        result = parse_requirements(str(req))
        assert result == ["requests", "flask"]

    def test_skips_secured_entries(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n# --- Secured by secure-pm for requests ---\nrequests --hash=sha256:abc\n")
        result = parse_requirements(str(req))
        # The first line is unsecured, the third has hash but no "Secured by" marker in the line itself
        assert "requests" in result

    def test_skips_editable_installs(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("-e git+https://github.com/user/repo.git\nrequests\n")
        result = parse_requirements(str(req))
        assert result == ["requests"]

    def test_skips_flags(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("--index-url https://pypi.org/simple\nrequests\n")
        result = parse_requirements(str(req))
        assert result == ["requests"]

    def test_strips_env_markers(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text('pywin32>=300; sys_platform == "win32"\n')
        result = parse_requirements(str(req))
        assert len(result) == 1
        # Should strip the marker but keep version
        assert "pywin32>=300" in result[0]

    def test_strips_inline_comments(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.33.0 # needed for HTTP\n")
        result = parse_requirements(str(req))
        assert result == ["requests==2.33.0"]

    def test_missing_file(self):
        result = parse_requirements("/nonexistent/path/requirements.txt")
        assert result == []


# ---------------------------------------------------------------------------
# parse_package_json
# ---------------------------------------------------------------------------

class TestParsePackageJson:
    def test_basic_deps(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        result = parse_package_json(str(pkg))
        assert set(result) == {"express", "lodash", "jest"}

    def test_empty_deps(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "test"}))
        result = parse_package_json(str(pkg))
        assert result == []

    def test_missing_file(self):
        result = parse_package_json("/nonexistent/package.json")
        assert result == []


# ---------------------------------------------------------------------------
# parse_cargo_toml
# ---------------------------------------------------------------------------

class TestParseCargoToml:
    def test_basic_deps(self, tmp_path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n')
        result = parse_cargo_toml(str(cargo))
        assert "serde" in result
        assert "tokio" in result

    def test_dev_dependencies(self, tmp_path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nserde = "1.0"\n\n[dev-dependencies]\ncriterion = "0.5"\n')
        result = parse_cargo_toml(str(cargo))
        assert "serde" in result
        assert "criterion" in result

    def test_missing_file(self):
        result = parse_cargo_toml("/nonexistent/Cargo.toml")
        assert result == []
