import os
import shutil
import hashlib
from rich.console import Console
from ..auditor.ai_agent import AIAuditor

console = Console()

class BaseManager:
    def __init__(self):
        self.auditor = AIAuditor()

    def generate_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def audit_only(self, package: str) -> tuple[bool, str]:
        """Downloads the package, runs the AI auditor, and cleans up without installing."""
        console.print(f"[bold magenta]Starting audit-only workflow for {package}...[/bold magenta]")
        archive_path, extract_dir = self.download(package)
        try:
            is_safe = self.auditor.audit_package_source(package, extract_dir)
            pkg_hash = self.generate_hash(archive_path) if is_safe else ""
            return is_safe, pkg_hash
        finally:
            self.cleanup(archive_path, extract_dir)

    def install(self, package: str):
        # 1. Download
        archive_path, extract_dir = self.download(package)
        try:
            # 2. Audit
            is_safe = self.auditor.audit_package_source(package, extract_dir)
            if not is_safe:
                raise Exception(f"Package '{package}' flagged as malicious by AI Agent!")

            # 3. Hash
            pkg_hash = self.generate_hash(archive_path)
            console.print(f"[cyan]Generated secure hash for {package}: {pkg_hash}[/cyan]")

            # 4. Pin
            self.pin_dependency(package, pkg_hash)

            # 5. Install
            self.perform_install(package, archive_path)
            
        finally:
            self.cleanup(archive_path, extract_dir)

    def download(self, package: str) -> tuple[str, str]:
        raise NotImplementedError

    def pin_dependency(self, package: str, pkg_hash: str, filepath: str = None):
        raise NotImplementedError

    def perform_install(self, package: str, archive_path: str):
        raise NotImplementedError

    def cleanup(self, archive_path: str, extract_dir: str):
        if os.path.exists(archive_path):
            os.remove(archive_path)
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
