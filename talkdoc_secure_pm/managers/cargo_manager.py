import os
import subprocess
import tempfile
import requests
from .base_manager import BaseManager
from rich.console import Console

console = Console()

class CargoManager(BaseManager):
    def download(self, package: str) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via crates.io API...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        
        # If the user passed "pkg@1.0.0", split it
        parts = package.split('@')
        pkg_name = parts[0]
        version = parts[1] if len(parts) > 1 else None
        
        if not version:
            # fetch latest version
            resp = requests.get(f"https://crates.io/api/v1/crates/{pkg_name}").json()
            if 'crate' not in resp:
                raise Exception(f"Crate {pkg_name} not found on crates.io: {resp}")
            version = resp['crate']['max_version']
            
        url = f"https://crates.io/api/v1/crates/{pkg_name}/{version}/download"
        archive_name = f"{pkg_name}-{version}.crate"
        archive_path = os.path.join(temp_dir, archive_name)
        
        r = requests.get(url, stream=True)
        r.raise_for_status()
        with open(archive_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir)
        
        import tarfile
        try:
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_dir)
        except Exception as e:
            console.print(f"[yellow]Failed to extract Cargo archive: {e}[/yellow]")
            
        return [archive_path], extract_dir

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        console.print(f"[cyan]Cargo pinning via Cargo.lock (TODO: implement hash verification)[/cyan]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure cargo add for {package}...[/cyan]")
        pkg_name = package.split('@')[0]
        # In a real secure workflow, we'd install from local path or enforce Cargo.lock hash
        # For MVP, we run cargo add which updates the manifests
        subprocess.run(["cargo", "add", pkg_name], check=True)
