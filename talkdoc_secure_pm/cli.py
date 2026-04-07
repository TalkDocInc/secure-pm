import argparse
import sys
from .managers.pip_manager import PipManager
from .managers.npm_manager import NpmManager
from .managers.cargo_manager import CargoManager
from .batch_auditor import run_audit
from rich.console import Console

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="Secure Package Manager - AI Audited Dependency Installation",
        prog="secure-pm"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # install command
    install_parser = subparsers.add_parser("install", help="Install a package with AI audit")
    install_parser.add_argument("manager", choices=["pip", "npm", "cargo"], help="Package manager")
    install_parser.add_argument("package", help="Package name to install")

    # audit-all command
    audit_parser = subparsers.add_parser("audit-all", help="Batch audit all dependencies in a directory")
    audit_parser.add_argument("directory", nargs="?", default=".", help="Directory to audit (default: current)")

    args = parser.parse_args()

    if args.command == "install":
        if args.manager == "pip":
            manager = PipManager()
        elif args.manager == "npm":
            manager = NpmManager()
        elif args.manager == "cargo":
            manager = CargoManager()
        else:
            console.print("[red]Unsupported package manager[/red]")
            sys.exit(1)

        try:
            console.print(f"[bold green]Installing {args.package} with AI audit...[/bold green]")
            manager.install(args.package)
            console.print(f"[green]Successfully installed {args.package}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to install {args.package}: {e}[/red]")
            sys.exit(1)

    elif args.command == "audit-all":
        try:
            run_audit(args.directory)
        except Exception as e:
            console.print(f"[red]Audit failed: {e}[/red]")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
