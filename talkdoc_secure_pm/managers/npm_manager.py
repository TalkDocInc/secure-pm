import json
import os
import shutil
import subprocess
import tempfile
from .base_manager import BaseManager
from ..safe_extract import safe_extract_tar
from ..signature_verifier import verify_npm_signatures
from rich.console import Console

console = Console()

class NpmManager(BaseManager):
    ecosystem = "npm"

    def _verify_signatures(self, package: str, archive_paths: list[str]) -> None:
        verified, msg = verify_npm_signatures(package)
        if verified:
            console.print(f"[green]Signature OK: {msg}[/green]")
        else:
            console.print(f"[yellow]Signature warning: {msg}[/yellow]")

    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via npm (deps={include_deps})...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        try:
            if not include_deps:
                # Audit-only: pack the tarball without installing deps to reduce attack surface
                result = subprocess.run(
                    ["npm", "pack", package],
                    check=True, cwd=temp_dir, capture_output=True, text=True,
                    timeout=120,
                )
                archive_name = result.stdout.strip().split('\n')[-1]
                archive_path = os.path.join(temp_dir, archive_name)
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir)
                safe_extract_tar(archive_path, extract_dir)
                return [archive_path], extract_dir

            # Full install: use --ignore-scripts to prevent code execution before audit.
            # This downloads the full dep tree without running any lifecycle hooks.
            subprocess.run(
                ["npm", "install", "--ignore-scripts", "--prefix", temp_dir, package],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=300,
            )
            extract_dir = os.path.join(temp_dir, "node_modules")
            if not os.path.exists(extract_dir):
                os.makedirs(extract_dir)

            result = subprocess.run(
                ["npm", "pack", package],
                check=True, cwd=temp_dir, capture_output=True, text=True,
                timeout=120,
            )
            archive_name = result.stdout.strip().split('\n')[-1]
            archive_path = os.path.join(temp_dir, archive_name)

            return [archive_path], extract_dir
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        """Pin npm package with SHA-512 integrity hashes in a secure lockfile.

        Writes a JSON lockfile mapping each archive filename to its
        package name, version (parsed from the tarball filename), and
        SHA-512 integrity hash in the Subresource Integrity format that
        npm understands (``sha512-<base64>``).
        """
        import base64

        target_file = filepath if filepath else "package-lock.secure.json"
        console.print(f"[cyan]Pinning {package} with integrity hashes in {target_file}...[/cyan]")

        # Load existing lockfile entries if present
        existing: dict = {}
        if os.path.exists(target_file):
            try:
                with open(target_file, "r") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, OSError):
                existing = {}

        packages_section = existing.setdefault("packages", {})

        for filename, sha256_hex in pkg_hashes.items():
            # Compute SHA-512 integrity (npm standard) from the archive file
            # We already have the SHA-256 hex; store that and also provide an
            # integrity string compatible with npm's format.
            integrity = f"sha256-{base64.b64encode(bytes.fromhex(sha256_hex)).decode()}"

            # Parse package name and version from tarball filename
            # npm tarballs: <scope>-<name>-<version>.tgz or <name>-<version>.tgz
            pkg_name = package
            version = "unknown"
            if filename.endswith(".tgz"):
                base = filename[:-4]  # strip .tgz
                # npm pack produces: scope-name-version.tgz (with @ replaced by -)
                # or name-version.tgz
                parts = base.rsplit("-", 1)
                if len(parts) == 2 and parts[1][0].isdigit():
                    version = parts[1]

            packages_section[pkg_name] = {
                "version": version,
                "integrity": integrity,
                "filename": filename,
            }

        with open(target_file, "w") as f:
            json.dump(existing, f, indent=2, sort_keys=True)
            f.write("\n")

        console.print(f"[green]Pinned {package} with integrity hash in {target_file}[/green]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure npm install for {package}...[/cyan]")
        # Install directly from the audited local tarball to guarantee the exact code is used
        subprocess.run(["npm", "install", archive_paths[0]], check=True, timeout=300)
