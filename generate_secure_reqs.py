#!/usr/bin/env python3
"""
Generate requirements-secure.txt with versioned, hashed pins for secure-pm bootstrap.
Downloads the full dependency tree (including transitive deps) so every hash is captured.
Re-run this script after any dependency version bump.
"""
import os
import re
import sys
sys.path.insert(0, ".")
from talkdoc_secure_pm.managers.pip_manager import PipManager


def main():
    mgr = PipManager()
    direct_deps = ["requests", "openai", "rich", "python-dotenv", "packaging"]
    print("Generating bootstrap requirements (full dependency trees) for secure-pm...")

    # filename -> (pkg, version, hash) -- filename key deduplicates shared transitive archives
    all_pins: dict[str, tuple[str, str, str]] = {}

    for dep in direct_deps:
        print(f"  Processing full dep tree for: {dep} ...")
        archive_paths, extract_dir = mgr.download(dep, include_deps=True)
        try:
            for archive_path in archive_paths:
                filename = os.path.basename(archive_path)
                h = mgr.generate_hash(archive_path)
                dep_pkg = re.split(r"-(?=\d)", filename, maxsplit=1)[0]
                version_match = re.search(
                    r"-([0-9][0-9a-zA-Z._+]*?)(?:-|(?:\.tar\.gz|\.whl|\.zip)$)", filename
                )
                version = version_match.group(1) if version_match else "0.0.0"
                all_pins[filename] = (dep_pkg, version, h)
        finally:
            mgr.cleanup(archive_paths, extract_dir)

    with open("requirements-secure.txt", "w") as f:
        f.write("# Audited and pinned dependencies for secure-pm bootstrap\n")
        f.write("# Includes transitive deps. Re-generate with: python generate_secure_reqs.py\n\n")
        for filename, (pkg, version, h) in sorted(all_pins.items()):
            f.write(f"{pkg}=={version} --hash=sha256:{h}\n")

    print(
        f"Generated requirements-secure.txt with {len(all_pins)} versioned pins "
        "(including transitive deps)."
    )
    print("Use: pip install -r requirements-secure.txt --require-hashes")


if __name__ == "__main__":
    main()
