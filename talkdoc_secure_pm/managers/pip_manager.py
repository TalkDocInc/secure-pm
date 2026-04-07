import os
import subprocess
import sys
import shutil
import tempfile
import re
from .base_manager import BaseManager
from ..safe_extract import safe_extract_zip, safe_extract_tar
from ..signature_verifier import verify_pip_provenance
from rich.console import Console

console = Console()

class PipManager(BaseManager):
    ecosystem = "pip"

    def _verify_signatures(self, package: str, archive_paths: list[str]) -> None:
        for archive_path in archive_paths:
            verified, msg = verify_pip_provenance(package, archive_path)
            if verified:
                console.print(f"[green]Provenance OK: {msg}[/green]")
            else:
                console.print(f"[yellow]Provenance warning: {msg}[/yellow]")

    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via pip (deps={include_deps})...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        try:
            # Use current Python's pip module for venv compatibility. --no-deps for audit reduces attack surface.
            pip_cmd = [sys.executable, "-m", "pip"]
            cmd = pip_cmd + ["download", "-d", temp_dir, package]
            if not include_deps:
                cmd = pip_cmd + ["download", "--no-deps", "-d", temp_dir, package]
            subprocess.run(
                cmd,
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=300,  # 5 min timeout to prevent hangs
            )

            files = os.listdir(temp_dir)
            if not files:
                raise Exception("No files downloaded.")

            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir)

            all_archives = []
            for archive_name in files:
                if archive_name == "extracted":
                    continue
                archive_path = os.path.join(temp_dir, archive_name)
                all_archives.append(archive_path)

                target_extract = os.path.join(extract_dir, archive_name)

                if archive_name.endswith('.whl') or archive_name.endswith('.zip'):
                    try:
                        os.makedirs(target_extract, exist_ok=True)
                        safe_extract_zip(archive_path, target_extract)
                    except Exception as e:
                        console.print(f"[yellow]Failed to extract {archive_name}: {e}[/yellow]")
                elif archive_name.endswith('.tar.gz'):
                    try:
                        os.makedirs(target_extract, exist_ok=True)
                        safe_extract_tar(archive_path, target_extract)
                    except Exception as e:
                        console.print(f"[yellow]Failed to extract {archive_name}: {e}[/yellow]")

            return all_archives, extract_dir
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        target_file = filepath if filepath else "requirements.txt"
        console.print(f"[cyan]Pinning {package} with secure hashes in {target_file}...[/cyan]")

        with open(target_file, "a") as f:
            f.write(f"\n# --- Secured by secure-pm for {package} ---\n")
            for filename, h in pkg_hashes.items():
                if any(filename.endswith(ext) for ext in ('.whl', '.tar.gz', '.zip')):
                    # Extract package name (before first digit-led version segment)
                    dep_pkg = re.split(r'-(?=\d)', filename, maxsplit=1)[0]
                    # Extract version from archive filename (PEP 440 style)
                    version_match = re.search(
                        r'-([0-9][0-9a-zA-Z._+]*?)(?:-|(?:\.tar\.gz|\.whl|\.zip)$)', filename
                    )
                    version = version_match.group(1) if version_match else None
                    if version:
                        f.write(f"{dep_pkg}=={version} --hash=sha256:{h}\n")
                    else:
                        f.write(f"{dep_pkg} --hash=sha256:{h}\n")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure pip install for {package}...[/cyan]")
        # Use current Python's pip for venv compatibility
        pip_cmd = [sys.executable, "-m", "pip"]
        subprocess.run(pip_cmd + ["install"] + archive_paths, check=True, timeout=600)
