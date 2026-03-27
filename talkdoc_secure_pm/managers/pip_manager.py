import os
import subprocess
import sys
import tempfile
import zipfile
import tarfile
import re
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class PipManager(BaseManager):
    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via pip (deps={include_deps})...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        # Use current Python's pip module for venv compatibility. --no-deps for audit reduces attack surface.
        pip_cmd = [sys.executable, "-m", "pip"]
        cmd = pip_cmd + ["download", "-d", temp_dir, package]
        if not include_deps:
            cmd = pip_cmd + ["download", "--no-deps", "-d", temp_dir, package]
        subprocess.run(
            cmd,
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
                try:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(target_extract)
                except Exception as e:
                    console.print(f"[yellow]Failed to extract {archive_name}: {e}[/yellow]")
            elif archive_name.endswith('.tar.gz'):
                try:
                    with tarfile.open(archive_path, 'r:gz') as tar_ref:
                        tar_ref.extractall(target_extract)
                except Exception as e:
                    console.print(f"[yellow]Failed to extract {archive_name}: {e}[/yellow]")
                
        return all_archives, extract_dir

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        target_file = filepath if filepath else "requirements.txt"
        console.print(f"[cyan]Pinning {package} with secure hashes in {target_file}...[/cyan]")
        
        with open(target_file, "a") as f:
            f.write(f"\n# --- Secured by secure-pm for {package} ---\n")
            for filename, h in pkg_hashes.items():
                if any(filename.endswith(ext) for ext in ('.whl', '.tar.gz', '.zip')):
                    # Extract package name (before first - followed by digit)
                    match = re.split(r'-(?=\d)', filename, maxsplit=1)
                    dep_pkg = match[0] if match else package
                    # For MVP, omit exact version (can be improved with metadata parsing)
                    f.write(f"{dep_pkg} --hash=sha256:{h}\n")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure pip install for {package}...[/cyan]")
        # Use current Python's pip for venv compatibility
        pip_cmd = [sys.executable, "-m", "pip"]
        subprocess.run(pip_cmd + ["install"] + archive_paths, check=True)
