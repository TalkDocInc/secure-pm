import os
import subprocess
import tempfile
from .base_manager import BaseManager
from rich.console import Console

console = Console()

import re

class PipManager(BaseManager):
    def download(self, package: str) -> tuple[list[str], str]:
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
        
        all_archives = []
        for archive_name in files:
            if archive_name == "extracted": continue
            archive_path = os.path.join(temp_dir, archive_name)
            all_archives.append(archive_path)
            
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
                
        return all_archives, extract_dir

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str = None):
        target_file = filepath if filepath else "requirements.txt"
        console.print(f"[cyan]Pinning {package} AND its dependencies in {target_file}...[/cyan]")
        
        with open(target_file, "a") as f:
            f.write(f"\n# --- Secured Tree for {package} ---\n")
            for filename, h in pkg_hashes.items():
                if filename.endswith('.whl') or filename.endswith('.tar.gz') or filename.endswith('.zip'):
                    dep_pkg = re.split(r'-(?=\d)', filename)[0]
                    f.write(f"{dep_pkg} --hash=sha256:{h}\n")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure pip install for {package}...[/cyan]")
        subprocess.run(["pip", "install"] + archive_paths, check=True)
