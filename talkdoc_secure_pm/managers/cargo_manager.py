import os
import shutil
import subprocess
import tempfile
import requests
from .base_manager import BaseManager
from ..safe_extract import safe_extract_tar
from rich.console import Console

console = Console()

class CargoManager(BaseManager):
    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via crates.io API (deps={include_deps})...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        try:
            # If the user passed "pkg@1.0.0", split it
            parts = package.split('@')
            pkg_name = parts[0]
            version = parts[1] if len(parts) > 1 else None

            if not version:
                # fetch latest version
                resp = requests.get(
                    f"https://crates.io/api/v1/crates/{pkg_name}",
                    timeout=30,
                    headers={"User-Agent": "secure-pm (https://github.com/TalkDocInc/secure-pm)"},
                ).json()
                if 'crate' not in resp:
                    raise Exception(f"Crate {pkg_name} not found on crates.io: {resp}")
                version = resp['crate']['max_version']

            url = f"https://crates.io/api/v1/crates/{pkg_name}/{version}/download"
            archive_name = f"{pkg_name}-{version}.crate"
            archive_path = os.path.join(temp_dir, archive_name)

            r = requests.get(
                url, stream=True, timeout=60,
                headers={"User-Agent": "secure-pm (https://github.com/TalkDocInc/secure-pm)"},
            )
            r.raise_for_status()
            with open(archive_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir)

            try:
                safe_extract_tar(archive_path, extract_dir)
            except Exception as e:
                console.print(f"[yellow]Failed to extract Cargo archive: {e}[/yellow]")

            return [archive_path], extract_dir
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        console.print(f"[cyan]Cargo pinning via Cargo.lock (TODO: implement hash verification)[/cyan]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure cargo install for {package}...[/cyan]")
        pkg_name = package.split('@')[0]
        # Install from the local audited archive path rather than re-fetching from registry.
        # This ensures the exact code that was audited is what gets installed.
        archive_path = archive_paths[0]
        # Extract the crate to a temp dir and install from local path
        extract_dir = tempfile.mkdtemp()
        try:
            safe_extract_tar(archive_path, extract_dir)
            # Find the extracted crate directory (usually pkg_name-version/)
            subdirs = [d for d in os.listdir(extract_dir)
                       if os.path.isdir(os.path.join(extract_dir, d))]
            if subdirs:
                crate_dir = os.path.join(extract_dir, subdirs[0])
            else:
                crate_dir = extract_dir
            subprocess.run(
                ["cargo", "install", "--path", crate_dir],
                check=True, timeout=600,
            )
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)
