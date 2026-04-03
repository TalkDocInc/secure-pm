"""Software Bill of Materials (SBOM) generation in CycloneDX 1.5 JSON format.

Generates a machine-readable inventory of all audited packages, their
versions, hashes, and audit status.  The output conforms to the CycloneDX
1.5 specification (https://cyclonedx.org/specification/overview/).

Usage from CLI::

    secure-pm sbom <directory>          # scan and generate sbom.cdx.json
    secure-pm sbom <directory> -o out.json
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone
from rich.console import Console

console = Console()


def _purl(ecosystem: str, name: str, version: str | None = None) -> str:
    """Build a Package URL (purl) string per https://github.com/package-url/purl-spec."""
    purl_type = {"pip": "pypi", "npm": "npm", "cargo": "cargo"}.get(ecosystem, ecosystem)
    base = f"pkg:{purl_type}/{name}"
    if version:
        base += f"@{version}"
    return base


def generate_sbom(
    packages: list[dict],
    output_path: str = "sbom.cdx.json",
    project_name: str = "secure-pm-audit",
) -> str:
    """Generate a CycloneDX 1.5 SBOM from a list of audited package dicts.

    Each dict in *packages* should have::

        {
            "name": "requests",
            "version": "2.33.0",            # optional
            "ecosystem": "pip",              # pip | npm | cargo
            "hashes": {"sha256": "abc..."},  # optional
            "audit_status": "approved",      # approved | rejected | skipped
            "filename": "requests-2.33.0-py3-none-any.whl",  # optional
        }

    Returns the path to the written SBOM file.
    """
    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    components = []
    for pkg in packages:
        name = pkg["name"]
        version = pkg.get("version", "unknown")
        ecosystem = pkg.get("ecosystem", "pip")

        component: dict = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": _purl(ecosystem, name, version if version != "unknown" else None),
        }

        # Add hashes if available
        hashes_list = []
        for algo, digest in pkg.get("hashes", {}).items():
            alg_label = {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1"}.get(algo, algo.upper())
            hashes_list.append({"alg": alg_label, "content": digest})
        if hashes_list:
            component["hashes"] = hashes_list

        # Store audit status as a property
        component["properties"] = [
            {"name": "secure-pm:audit-status", "value": pkg.get("audit_status", "unknown")},
        ]
        if pkg.get("filename"):
            component["properties"].append(
                {"name": "secure-pm:filename", "value": pkg["filename"]}
            )

        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "TalkDoc Inc.",
                    "name": "secure-pm",
                    "version": "0.3.0",
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
            },
        },
        "components": components,
    }

    with open(output_path, "w") as f:
        json.dump(sbom, f, indent=2)
        f.write("\n")

    console.print(f"[bold green]SBOM written to {output_path} ({len(components)} components)[/bold green]")
    return output_path


def generate_sbom_from_directory(base_dir: str, output_path: str = "sbom.cdx.json") -> str:
    """Scan *base_dir* for manifest files and produce an SBOM listing all
    discovered packages (without running the full audit — just cataloguing).

    This is a lightweight inventory operation.
    """
    import glob
    import tomllib

    packages: list[dict] = []

    # --- Python requirements ---
    for req_file in glob.glob(os.path.join(base_dir, "**/requirements.txt"), recursive=True):
        if any(skip in req_file.split(os.sep) for skip in ("venv", ".venv", "node_modules")):
            continue
        try:
            with open(req_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    spec = re.split(r"\s*[;#]", line)[0].strip()
                    spec = re.sub(r"\s+--hash=\S+", "", spec).strip()
                    if not spec:
                        continue
                    # Parse name and version
                    m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:[=~!<>]+\s*(\S+))?", spec)
                    if m:
                        name, version = m.group(1), m.group(2) or "unknown"
                        # Extract hash if present on original line
                        hashes = {}
                        hash_match = re.search(r"--hash=sha256:(\S+)", line)
                        if hash_match:
                            hashes["sha256"] = hash_match.group(1)
                        packages.append({
                            "name": name, "version": version,
                            "ecosystem": "pip", "hashes": hashes,
                            "audit_status": "catalogued",
                        })
        except Exception:
            pass

    # --- NPM package.json ---
    for pkg_file in glob.glob(os.path.join(base_dir, "**/package.json"), recursive=True):
        if "node_modules" in pkg_file.split(os.sep):
            continue
        try:
            with open(pkg_file) as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name, ver_spec in data.get(section, {}).items():
                    packages.append({
                        "name": name,
                        "version": ver_spec.lstrip("^~>=<"),
                        "ecosystem": "npm",
                        "audit_status": "catalogued",
                    })
        except Exception:
            pass

    # --- Cargo.toml ---
    for cargo_file in glob.glob(os.path.join(base_dir, "**/Cargo.toml"), recursive=True):
        if "target" in cargo_file.split(os.sep):
            continue
        try:
            with open(cargo_file, "rb") as f:
                data = tomllib.load(f)
            for section in ("dependencies", "dev-dependencies"):
                for name, spec in data.get(section, {}).items():
                    version = "unknown"
                    if isinstance(spec, str):
                        version = spec
                    elif isinstance(spec, dict):
                        version = spec.get("version", "unknown")
                    packages.append({
                        "name": name, "version": version,
                        "ecosystem": "cargo",
                        "audit_status": "catalogued",
                    })
        except Exception:
            pass

    return generate_sbom(packages, output_path=output_path, project_name=os.path.basename(os.path.abspath(base_dir)))
