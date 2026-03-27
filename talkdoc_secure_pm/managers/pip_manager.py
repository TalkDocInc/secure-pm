import os
import subprocess
import tempfile
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class PipManager(BaseManager):
    def download(self, package: str) -> tuple[str, str]:
        console.print(f"[cyan]Downloading {package} AND its dependencies via pip...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        subprocess.run(
            ["pip", "download", "-d", temp_dir, package],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
        files = os.listdir(temp_dir)
        if not files:
            raise Exception("No files downloaded.")
            
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        
        main_archive = None
        for archive_name in files:
            if archive_name == "extracted": continue
            if package.lower() in archive_name.lower() or not main_archive:
                main_archive = os.path.join(temp_dir, archive_name)
                
            archive_path = os.path.join(temp_dir, archive_name)
            target_extract = os.path.join(extract_dir, archive_name)
            
            if archive_name.endswith('.whl') or archive_name.endswith('.zip'):
                import zipfile
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(target_extract)
                except Exception: pass
            elif archive_name.endswith('.tar.gz'):
                import tarfile
                try:
                    with tarfile.open(archive_path, 'r:gz') as tar_ref:
                        tar_ref.extractall(target_extract)
                except Exception: pass
                
        return main_archive, extract_dir

    def pin_dependency(self, package: str, pkg_hash: str, filepath: str = None):
        target_file = filepath if filepath else "requirements.txt"
        console.print(f"[cyan]Pinning {package} heavily in {target_file}...[/cyan]")
        # Append to requirements.txt securely
        with open(target_file, "a") as f:
            f.write(f"{package} --hash=sha256:{pkg_hash}\n")

    def perform_install(self, package: str, archive_path: str):
        console.print(f"[cyan]Running secure pip install for {package}...[/cyan]")
        subprocess.run(["pip", "install", archive_path], check=True)
