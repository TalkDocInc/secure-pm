import os
import re
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

    def audit_only(self, package: str) -> tuple[bool, dict[str, str]]:
        """Downloads the package (no deps for audit to reduce attack surface), runs the AI auditor, and cleans up without installing."""
        console.print(f"[bold magenta]Starting audit-only workflow for {package}...[/bold magenta]")
        archive_paths, extract_dir = self.download(package, include_deps=False)
        try:
            is_safe = self.auditor.audit_package_source(package, extract_dir)
            pkg_hashes = {}
            if is_safe:
                for p in archive_paths:
                    pkg_hashes[os.path.basename(p)] = self.generate_hash(p)
            return is_safe, pkg_hashes
        finally:
            self.cleanup(archive_paths, extract_dir)

    def install(self, package: str):
        # 1. Download (with deps for full install)
        archive_paths, extract_dir = self.download(package, include_deps=True)
        try:
            # 2. Audit each dependency in the tree independently
            dep_dirs = sorted(
                d for d in os.listdir(extract_dir)
                if os.path.isdir(os.path.join(extract_dir, d))
            )
            if dep_dirs:
                for dep_dir in dep_dirs:
                    dep_path = os.path.join(extract_dir, dep_dir)
                    # Extract package name: strip version suffix (e.g. "requests-2.33.0-.." -> "requests")
                    dep_name = re.split(r'-[0-9]', dep_dir)[0]
                    console.print(f"[magenta]Auditing dependency: {dep_name}[/magenta]")
                    if not self.auditor.audit_package_source(dep_name, dep_path):
                        raise Exception(
                            f"Dependency '{dep_name}' in tree for '{package}' flagged as malicious!"
                        )
            else:
                # Fallback: audit the combined extract dir if nothing extracted
                if not self.auditor.audit_package_source(package, extract_dir):
                    raise Exception(f"Package '{package}' flagged as malicious by AI Agent!")

            # 3. Hash
            pkg_hashes = {}
            for p in archive_paths:
                h = self.generate_hash(p)
                pkg_hashes[os.path.basename(p)] = h
                console.print(f"[cyan]Generated secure hash for {os.path.basename(p)}: {h}[/cyan]")

            # 4. Pin
            self.pin_dependency(package, pkg_hashes)

            # 5. Install
            self.perform_install(package, archive_paths)

        finally:
            self.cleanup(archive_paths, extract_dir)

    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        raise NotImplementedError

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        raise NotImplementedError

    def perform_install(self, package: str, archive_paths: list[str]):
        raise NotImplementedError

    def cleanup(self, archive_paths: list[str], extract_dir: str):
        # Remove the entire parent temp dir (contains both the archive files and extract_dir).
        # Using os.path.dirname works because extract_dir is always a direct child of temp_dir.
        temp_dir = os.path.dirname(extract_dir)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
