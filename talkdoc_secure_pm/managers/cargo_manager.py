import json
import os
import re
import shutil
import subprocess
import tempfile
import requests as http_requests
from .base_manager import BaseManager
from ..safe_extract import safe_extract_tar
from ..signature_verifier import verify_cargo_checksum
from rich.console import Console

console = Console()

_CRATES_IO_UA = {"User-Agent": "secure-pm (https://github.com/TalkDocInc/secure-pm)"}


class CargoManager(BaseManager):
    ecosystem = "cargo"

    def _verify_signatures(self, package: str, archive_paths: list[str]) -> None:
        for archive_path in archive_paths:
            verified, msg = verify_cargo_checksum(package, archive_path)
            if verified:
                console.print(f"[green]Checksum OK: {msg}[/green]")
            else:
                console.print(f"[yellow]Checksum warning: {msg}[/yellow]")

    def download(self, package: str, include_deps: bool = True) -> tuple[list[str], str]:
        console.print(f"[cyan]Downloading {package} via crates.io API (deps={include_deps})...[/cyan]")
        temp_dir = tempfile.mkdtemp()
        try:
            parts = package.split('@')
            pkg_name = parts[0]
            version = parts[1] if len(parts) > 1 else None

            if not version:
                resp = http_requests.get(
                    f"https://crates.io/api/v1/crates/{pkg_name}",
                    timeout=30, headers=_CRATES_IO_UA,
                ).json()
                if 'crate' not in resp:
                    raise Exception(f"Crate {pkg_name} not found on crates.io: {resp}")
                version = resp['crate']['max_version']

            all_archives = []
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir)

            # Always download the primary crate
            primary_archive = self._download_crate(pkg_name, version, temp_dir)
            all_archives.append(primary_archive)
            try:
                safe_extract_tar(primary_archive, extract_dir)
            except Exception as e:
                console.print(f"[yellow]Failed to extract {pkg_name}-{version}: {e}[/yellow]")

            # If include_deps, also download transitive dependencies
            if include_deps:
                deps = self._resolve_transitive_deps(pkg_name, version)
                for dep_name, dep_version in deps:
                    try:
                        dep_archive = self._download_crate(dep_name, dep_version, temp_dir)
                        all_archives.append(dep_archive)
                        safe_extract_tar(dep_archive, extract_dir)
                    except Exception as e:
                        console.print(f"[yellow]Failed to download/extract dep {dep_name}@{dep_version}: {e}[/yellow]")

            return all_archives, extract_dir
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def _download_crate(self, name: str, version: str, dest_dir: str) -> str:
        """Download a single crate archive to dest_dir and return its path."""
        url = f"https://crates.io/api/v1/crates/{name}/{version}/download"
        archive_name = f"{name}-{version}.crate"
        archive_path = os.path.join(dest_dir, archive_name)

        if os.path.exists(archive_path):
            return archive_path  # already downloaded (shared transitive dep)

        r = http_requests.get(url, stream=True, timeout=60, headers=_CRATES_IO_UA)
        r.raise_for_status()
        with open(archive_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return archive_path

    def _resolve_transitive_deps(self, name: str, version: str, _seen: set | None = None) -> list[tuple[str, str]]:
        """Resolve direct (non-optional, non-dev) dependencies from crates.io metadata.

        Does a breadth-first traversal of the dependency graph. Returns a
        flat list of ``(name, version)`` tuples for every transitive
        dependency.  ``_seen`` prevents infinite loops on diamond deps.
        """
        if _seen is None:
            _seen = {f"{name}@{version}"}
        result: list[tuple[str, str]] = []

        try:
            resp = http_requests.get(
                f"https://crates.io/api/v1/crates/{name}/{version}/dependencies",
                timeout=30, headers=_CRATES_IO_UA,
            ).json()
        except Exception as e:
            console.print(f"[yellow]Failed to resolve deps for {name}@{version}: {e}[/yellow]")
            return result

        for dep in resp.get("dependencies", []):
            if dep.get("kind") == "dev" or dep.get("optional", False):
                continue
            dep_name = dep["crate_id"]
            # Resolve the latest version that matches the requirement
            dep_version = self._resolve_version(dep_name, dep.get("req", "*"))
            if not dep_version:
                continue
            key = f"{dep_name}@{dep_version}"
            if key in _seen:
                continue
            _seen.add(key)
            result.append((dep_name, dep_version))
            # Recurse into sub-deps
            result.extend(self._resolve_transitive_deps(dep_name, dep_version, _seen))

        return result

    def _resolve_version(self, name: str, _req: str) -> str | None:
        """Resolve the latest version of a crate on crates.io.

        For simplicity we just fetch the max (newest) version rather than
        doing full semver constraint solving against *_req*.
        """
        try:
            resp = http_requests.get(
                f"https://crates.io/api/v1/crates/{name}",
                timeout=30, headers=_CRATES_IO_UA,
            ).json()
            return resp.get("crate", {}).get("max_version")
        except Exception:
            return None

    def pin_dependency(self, package: str, pkg_hashes: dict[str, str], filepath: str | None = None):
        """Pin cargo crate hashes in a secure lockfile (JSON format).

        Creates/updates a ``Cargo.lock.secure.json`` file that records the
        SHA-256 checksum for every audited crate archive.  This file can be
        checked into version control and verified before future installs.
        """
        target_file = filepath if filepath else "Cargo.lock.secure.json"
        console.print(f"[cyan]Pinning {package} with checksums in {target_file}...[/cyan]")

        existing: dict = {}
        if os.path.exists(target_file):
            try:
                with open(target_file, "r") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, OSError):
                existing = {}

        packages_section = existing.setdefault("packages", {})

        for filename, sha256_hex in pkg_hashes.items():
            # Parse name and version from crate filename: name-version.crate
            crate_name = package.split('@')[0]
            version = "unknown"
            if filename.endswith(".crate"):
                base = filename[:-6]  # strip .crate
                # filename is name-version.crate
                match = re.match(r'^(.+)-(\d[\d.]*(?:[-+]\S*)?)$', base)
                if match:
                    crate_name = match.group(1)
                    version = match.group(2)

            packages_section[f"{crate_name}@{version}"] = {
                "name": crate_name,
                "version": version,
                "checksum": f"sha256:{sha256_hex}",
                "filename": filename,
            }

        with open(target_file, "w") as f:
            json.dump(existing, f, indent=2, sort_keys=True)
            f.write("\n")

        console.print(f"[green]Pinned {package} with checksums in {target_file}[/green]")

    def perform_install(self, package: str, archive_paths: list[str]):
        console.print(f"[cyan]Running secure cargo install for {package}...[/cyan]")
        pkg_name = package.split('@')[0]
        # Install from the local audited archive path rather than re-fetching from registry.
        archive_path = archive_paths[0]
        extract_dir = tempfile.mkdtemp()
        try:
            safe_extract_tar(archive_path, extract_dir)
            subdirs = [d for d in os.listdir(extract_dir)
                       if os.path.isdir(os.path.join(extract_dir, d))]
            if subdirs:
                crate_dir = os.path.join(extract_dir, subdirs[0])
            else:
                crate_dir = extract_dir
            subprocess.run(
                ["cargo", "install", "--path", crate_dir],
                check=True, timeout=600,
            )
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)
