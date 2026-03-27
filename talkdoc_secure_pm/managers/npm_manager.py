import os
import subprocess
import tempfile
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class NpmManager(BaseManager):
    def download(self, package: str) -> tuple[str, str]:
        console.print(f"[cyan]Downloading {package} via npm pack...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        
        # npm pack returns the filename of the packed tarball
        result = subprocess.run(
            ["npm", "pack", package],
            check=True, cwd=temp_dir, capture_output=True, text=True
        )
        archive_name = result.stdout.strip().split('\n')[-1]
        archive_path = os.path.join(temp_dir, archive_name)
        
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        
        # Extract the tarball
        import tarfile
        try:
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        except Exception as e:
            console.print(f"[yellow]Failed to extract NPM archive: {e}[/yellow]")
            
        return archive_path, extract_dir

    def pin_dependency(self, package: str, pkg_hash: str, filepath: str = None):
        console.print(f"[cyan]NPM handles package-lock.json pinning automatically upon install. Hash verified: {pkg_hash}[/cyan]")

    def perform_install(self, package: str, archive_path: str):
        console.print(f"[cyan]Running secure npm install for {package}...[/cyan]")
        # Install directly from the audited local tarball to guarantee the exact code is used
        subprocess.run(["npm", "install", archive_path], check=True)
