import argparse
import sys
from dotenv import load_dotenv
load_dotenv()
from rich.console import Console
from .managers.pip_manager import PipManager
from .managers.npm_manager import NpmManager
from .managers.cargo_manager import CargoManager

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="Secure Package Manager - Audits and pins dependencies securely using AI."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'install' command
    install_parser = subparsers.add_parser("install", help="Install a package securely (audits -> pins -> installs)")
    install_parser.add_argument("ecosystem", choices=["pip", "npm", "cargo"], help="The package manager ecosystem")
    install_parser.add_argument("package", help="The package name (and optional version) to install")

    # 'audit-all' command
    audit_parser = subparsers.add_parser("audit-all", help="Audit all currently installed packages across a directory")
    audit_parser.add_argument("directory", nargs="?", default=".", help="The root directory to scan for lockfiles")

    args = parser.parse_args()

    if args.command == "install":
        console.print(f"[bold blue]Starting secure install for {args.ecosystem} package: {args.package}[/bold blue]")
        
        if args.ecosystem == "pip":
            manager = PipManager()
        elif args.ecosystem == "npm":
            manager = NpmManager()
        elif args.ecosystem == "cargo":
            manager = CargoManager()
        else:
            console.print(f"[bold red]Unsupported ecosystem: {args.ecosystem}[/bold red]")
            sys.exit(1)

        try:
            manager.install(args.package)
            console.print(f"[bold green]Successfully installed and secured {args.package}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Installation failed: {e}[/bold red]")
            sys.exit(1)
            
    elif args.command == "audit-all":
        # Pass the directory to the audit script wrapper, or just run main logic
        from .batch_auditor import run_audit
        run_audit(args.directory)

if __name__ == "__main__":
    main()
