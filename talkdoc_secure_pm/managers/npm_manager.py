import os
import shutil
import subprocess
import tarfile
import tempfile
from .base_manager import BaseManager
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
                    check=True, cwd=temp_dir, capture_output=True, text=True
                )
                archive_name = result.stdout.strip().split('\n')[-1]
                archive_path = os.path.join(temp_dir, archive_name)
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir)
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
                return [archive_path], extract_dir

            # Full install: capture full dep tree in node_modules for auditing
            subprocess.run(
                ["npm", "install", "--prefix", temp_dir, package],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            extract_dir = os.path.join(temp_dir, "node_modules")
            if not os.path.exists(extract_dir):
                os.makedirs(extract_dir)

            result = subprocess.run(
                ["npm", "pack", package],
                check=True, cwd=temp_dir, capture_output=True, text=True
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
        subprocess.run(["npm", "install", archive_paths[0]], check=True)
