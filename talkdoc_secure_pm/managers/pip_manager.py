import os
import subprocess
import tempfile
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class PipManager(BaseManager):
    def download(self, package: str) -> tuple[str, str]:
        console.print(f"[cyan]Downloading {package} via pip...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        subprocess.run(
            ["pip", "download", "--no-deps", "-d", temp_dir, package],
            check=True, stdout=subprocess.DEVNULL
        )
        
        # Find the downloaded file
        files = os.listdir(temp_dir)
        if not files:
            raise Exception("No files downloaded.")
        archive_name = files[0]
        archive_path = os.path.join(temp_dir, archive_name)
        
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        
        # Extract based on type (whl is just a zip, tar.gz)
        if archive_name.endswith('.whl') or archive_name.endswith('.zip'):
            import zipfile
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_name.endswith('.tar.gz'):
            import tarfile
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        else:
            console.print(f"[yellow]Unknown archive format: {archive_name}, continuing without extraction...[/yellow]")
            
        # Return path to file and path to extracted contents
        return archive_path, extract_dir

    def pin_dependency(self, package: str, pkg_hash: str):
        console.print(f"[cyan]Pinning {package} in requirements.txt...[/cyan]")
        # Append to requirements.txt securely
        with open("requirements.txt", "a") as f:
            f.write(f"{package} --hash=sha256:{pkg_hash}\n")

    def perform_install(self, package: str, archive_path: str):
        console.print(f"[cyan]Running secure pip install for {package}...[/cyan]")
        subprocess.run(["pip", "install", archive_path], check=True)
