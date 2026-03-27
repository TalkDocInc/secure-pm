import os
import subprocess
import tempfile
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class NpmManager(BaseManager):
    def download(self, package: str) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} AND dependencies via npm...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        
        # Install privately to extract the full dependency tree into node_modules safely
        subprocess.run(
            ["npm", "install", "--prefix", temp_dir, package],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        extract_dir = os.path.join(temp_dir, "node_modules")
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir)
        
        # npm pack still used to get the standalone tarball for hash returning
        result = subprocess.run(
            ["npm", "pack", package],
            check=True, cwd=temp_dir, capture_output=True, text=True
        )
        archive_name = result.stdout.strip().split('\n')[-1]
        archive_path = os.path.join(temp_dir, archive_name)
            
        return [archive_path], extract_dir

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        console.print(f"[cyan]NPM pinning via package-lock.json (TODO: implement hash verification)[/cyan]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure npm install for {package}...[/cyan]")
        # Install directly from the audited local tarball to guarantee the exact code is used
        subprocess.run(["npm", "install", archive_paths[0]], check=True)
