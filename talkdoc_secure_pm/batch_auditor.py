import os
import glob
import json
import re
from dotenv import load_dotenv
load_dotenv()
from rich.console import Console

from talkdoc_secure_pm.managers.pip_manager import PipManager
from talkdoc_secure_pm.managers.npm_manager import NpmManager
from talkdoc_secure_pm.managers.cargo_manager import CargoManager

try:
    import tomllib
except ImportError:
    import tomli as tomllib

console = Console()

def parse_requirements(filepath: str) -> list[str]:
    packages = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-e') or line.startswith('--'):
                    continue
                # strip out version pins for downloading the package base logic
                pkg = re.split(r'[=><~]+', line)[0].strip()
                # Ignore paths or env markers for simple extraction
                pkg = pkg.split(';')[0].strip()
                if pkg:
                    packages.append(pkg)
    except Exception as e:
        console.print(f"[red]Error parsing {filepath}: {e}[/red]")
    return packages

def parse_package_json(filepath: str) -> list[str]:
    packages = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})
            packages.extend(deps.keys())
            packages.extend(dev_deps.keys())
    except Exception as e:
        console.print(f"[red]Error parsing {filepath}: {e}[/red]")
    return packages

def parse_cargo_toml(filepath: str) -> list[str]:
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
            deps = data.get('dependencies', {})
            dev_deps = data.get('dev-dependencies', {})
            # toml keys are the package names
            packages.extend(deps.keys())
            packages.extend(dev_deps.keys())
    except Exception as e:
        console.print(f"[red]Error parsing {filepath}: {e}[/red]")
    return list(set(packages))

def run_audit(base_dir: str = "."):
    console.print(f"[bold blue]Starting REAL Batch Audit in {base_dir} using AI endpoint...[/bold blue]")
    
    req_files = glob.glob(os.path.join(base_dir, "**/requirements.txt"), recursive=True)
    pkg_files = glob.glob(os.path.join(base_dir, "**/package.json"), recursive=True)
    cargo_files = glob.glob(os.path.join(base_dir, "**/Cargo.toml"), recursive=True)
    
    # Filter out venvs / node_modules to avoid parsing lockfiles/built assets
    req_files = [f for f in req_files if 'venv' not in f and 'env' not in f and 'node_modules' not in f]
    pkg_files = [f for f in pkg_files if 'node_modules' not in f]
    cargo_files = [f for f in cargo_files if 'target' not in f]
    
    console.print(f"Found {len(req_files)} Py requirements, {len(pkg_files)} NPM package.json files, and {len(cargo_files)} Cargo.toml files.")
    
    pip_mgr = PipManager()
    npm_mgr = NpmManager()
    cargo_mgr = CargoManager()
    
    total_audited = 0
    unsafe_packages = []
    
    # Audit Python
    for f in req_files:
        console.print(f"\\n[cyan]Parsing {f}[/cyan]")
        pkgs = parse_requirements(f)
        for p in pkgs:
            try:
                is_safe, pkg_hash = pip_mgr.audit_only(p)
                if not is_safe:
                    unsafe_packages.append((f, p))
                else:
                    secure_file = f + ".secure"
                    pip_mgr.pin_dependency(p, pkg_hash, filepath=secure_file)
            except Exception as e:
                console.print(f"[yellow]Failed to audit pip package {p}: {e}[/yellow]")
            total_audited += 1

    # Audit NPM
    for f in pkg_files:
        console.print(f"\\n[cyan]Parsing {f}[/cyan]")
        pkgs = parse_package_json(f)
        for p in pkgs:
            try:
                is_safe, pkg_hash = npm_mgr.audit_only(p)
                if not is_safe:
                    unsafe_packages.append((f, p))
            except Exception as e:
                console.print(f"[yellow]Failed to audit npm package {p}: {e}[/yellow]")
            total_audited += 1

    # Audit Cargo
    for f in cargo_files:
        console.print(f"\\n[cyan]Parsing {f}[/cyan]")
        pkgs = parse_cargo_toml(f)
        for p in pkgs:
            try:
                is_safe, pkg_hash = cargo_mgr.audit_only(p)
                if not is_safe:
                    unsafe_packages.append((f, p))
            except Exception as e:
                console.print(f"[yellow]Failed to audit cargo package {p}: {e}[/yellow]")
            total_audited += 1

    console.print(f"\\n[bold green]Audit Complete. Total packages audited: {total_audited}[/bold green]")
    if unsafe_packages:
        console.print("[bold red]WARNING: The following packages were flagged as unsafe by the AI:[/bold red]")
        for f, p in unsafe_packages:
            console.print(f" - {p} (from {f})")
    else:
        console.print("[bold green]All packages appear safe![/bold green]")

if __name__ == "__main__":
    import sys
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    run_audit(directory)
