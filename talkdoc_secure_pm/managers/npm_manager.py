import os
import shutil
import subprocess
import tempfile
from .base_manager import BaseManager
from ..safe_extract import safe_extract_tar
from rich.console import Console

console = Console()

class NpmManager(BaseManager):
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
        console.print(f"[cyan]NPM pinning via package-lock.json (TODO: implement hash verification)[/cyan]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure npm install for {package}...[/cyan]")
        # Install directly from the audited local tarball to guarantee the exact code is used
        subprocess.run(["npm", "install", archive_paths[0]], check=True, timeout=300)
