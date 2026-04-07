"""Tests for SBOM generation (CycloneDX format)."""
import json
import os


from talkdoc_secure_pm.sbom import generate_sbom, generate_sbom_from_directory


class TestGenerateSbom:
    def test_basic_sbom_structure(self, tmp_path):
        packages = [
            {
                "name": "requests",
                "version": "2.33.0",
                "ecosystem": "pip",
                "hashes": {"sha256": "abc123"},
                "audit_status": "approved",
                "filename": "requests-2.33.0-py3-none-any.whl",
            },
            {
                "name": "express",
                "version": "4.18.0",
                "ecosystem": "npm",
                "audit_status": "rejected",
            },
        ]
        output = str(tmp_path / "test.cdx.json")
        result = generate_sbom(packages, output_path=output)

        assert os.path.exists(result)
        with open(result) as f:
            sbom = json.load(f)

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 2

    def test_purl_format(self, tmp_path):
        packages = [
            {"name": "requests", "version": "2.33.0", "ecosystem": "pip", "audit_status": "approved"},
            {"name": "serde", "version": "1.0.0", "ecosystem": "cargo", "audit_status": "approved"},
        ]
        output = str(tmp_path / "test.cdx.json")
        generate_sbom(packages, output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        purls = [c["purl"] for c in sbom["components"]]
        assert "pkg:pypi/requests@2.33.0" in purls
        assert "pkg:cargo/serde@1.0.0" in purls

    def test_hashes_included(self, tmp_path):
        packages = [
            {
                "name": "flask",
                "version": "3.0.0",
                "ecosystem": "pip",
                "hashes": {"sha256": "deadbeef"},
                "audit_status": "approved",
            },
        ]
        output = str(tmp_path / "test.cdx.json")
        generate_sbom(packages, output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        component = sbom["components"][0]
        assert component["hashes"][0]["alg"] == "SHA-256"
        assert component["hashes"][0]["content"] == "deadbeef"

    def test_audit_status_property(self, tmp_path):
        packages = [
            {"name": "evil-pkg", "version": "0.1", "ecosystem": "pip", "audit_status": "rejected"},
        ]
        output = str(tmp_path / "test.cdx.json")
        generate_sbom(packages, output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
        assert props["secure-pm:audit-status"] == "rejected"

    def test_empty_packages(self, tmp_path):
        output = str(tmp_path / "test.cdx.json")
        generate_sbom([], output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        assert sbom["components"] == []

    def test_metadata_fields(self, tmp_path):
        output = str(tmp_path / "test.cdx.json")
        generate_sbom([], output_path=output, project_name="my-app")

        with open(output) as f:
            sbom = json.load(f)

        assert sbom["metadata"]["component"]["name"] == "my-app"
        assert sbom["metadata"]["tools"][0]["name"] == "secure-pm"
        assert "timestamp" in sbom["metadata"]
        assert sbom["serialNumber"].startswith("urn:uuid:")


class TestGenerateSbomFromDirectory:
    def test_scans_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.33.0\nflask>=3.0\n")

        output = str(tmp_path / "sbom.cdx.json")
        generate_sbom_from_directory(str(tmp_path), output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        names = [c["name"] for c in sbom["components"]]
        assert "requests" in names
        assert "flask" in names

    def test_scans_package_json(self, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.0.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))

        output = str(tmp_path / "sbom.cdx.json")
        generate_sbom_from_directory(str(tmp_path), output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        names = [c["name"] for c in sbom["components"]]
        assert "express" in names
        assert "jest" in names

    def test_scans_cargo_toml(self, tmp_path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[package]\nname = "myapp"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n')

        output = str(tmp_path / "sbom.cdx.json")
        generate_sbom_from_directory(str(tmp_path), output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        names = [c["name"] for c in sbom["components"]]
        assert "serde" in names

    def test_skips_venv(self, tmp_path):
        venv_dir = tmp_path / "venv"
        venv_dir.mkdir()
        req = venv_dir / "requirements.txt"
        req.write_text("should-be-skipped\n")

        output = str(tmp_path / "sbom.cdx.json")
        generate_sbom_from_directory(str(tmp_path), output_path=output)

        with open(output) as f:
            sbom = json.load(f)

        names = [c["name"] for c in sbom["components"]]
        assert "should-be-skipped" not in names
