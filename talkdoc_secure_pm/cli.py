import argparse
import sys


from .managers.pip_manager import PipManager
from .managers.npm_manager import NpmManager
from .managers.cargo_manager import CargoManager

from . import logger


def main():
    from dotenv import load_dotenv
    load_dotenv()
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

    # 'sbom' command
    sbom_parser = subparsers.add_parser("sbom", help="Generate a CycloneDX SBOM from project manifests")
    sbom_parser.add_argument("directory", nargs="?", default=".", help="The root directory to scan")
    sbom_parser.add_argument("-o", "--output", default="sbom.cdx.json", help="Output file path (default: sbom.cdx.json)")

    # 'cache' command
    cache_parser = subparsers.add_parser("cache", help="Manage the persistent audit cache")
    cache_sub = cache_parser.add_subparsers(dest="cache_action", required=True)
    cache_sub.add_parser("stats", help="Show cache statistics")
    cache_sub.add_parser("clear", help="Clear all cached audit results")
    cache_sub.add_parser("prune", help="Remove expired cache entries (older than 30 days)")

    # 'verify' command
    verify_parser = subparsers.add_parser("verify", help="Verify package signatures/provenance without installing")
    verify_parser.add_argument("ecosystem", choices=["pip", "npm", "cargo"], help="The package manager ecosystem")
    verify_parser.add_argument("package", help="The package to verify")

    args = parser.parse_args()

    if args.command == "install":
        logger.info(f"[bold blue]Starting secure install for {args.ecosystem} package: {args.package}[/bold blue]")


        if args.ecosystem == "pip":
            manager = PipManager()
        elif args.ecosystem == "npm":
            manager = NpmManager()
        elif args.ecosystem == "cargo":
            manager = CargoManager()
        else:
            logger.error(f"[bold red]Unsupported ecosystem: {args.ecosystem}[/bold red]")

            sys.exit(1)

        try:
            manager.install(args.package)
            logger.info(f"[bold green]Successfully installed and secured {args.package}[/bold green]")
        except RuntimeError as e:
            logger.error(f"[bold red]Installation failed: {e}[/bold red]")
            sys.exit(1)


    elif args.command == "audit-all":
        from .batch_auditor import run_audit
        run_audit(args.directory)

    elif args.command == "sbom":
        from .sbom import generate_sbom_from_directory
        output = generate_sbom_from_directory(args.directory, output_path=args.output)
        logger.info(f"[bold green]SBOM saved to {output}[/bold green]")


    elif args.command == "cache":
        from .auditor.cache import cache_stats, cache_clear, cache_prune
        if args.cache_action == "stats":
            stats = cache_stats()
            logger.info(f"[cyan]Audit cache statistics:[/cyan]")
            logger.info(f"  Total entries:  {stats['total']}")
            logger.info(f"  Approved:       {stats['approved']}")
            logger.info(f"  Rejected:       {stats['rejected']}")
            if stats['oldest_timestamp']:
                from datetime import datetime, timezone
                oldest = datetime.fromtimestamp(stats['oldest_timestamp'], tz=timezone.utc)
                logger.info(f"  Oldest entry:   {oldest.strftime('%Y-%m-%d %H:%M:%S UTC')}")


</xai:function_call name="edit_file">
<parameter name="path">talkdoc_secure_pm/cli.py
            console.print(f"  Approved:       {stats['approved']}")
            console.print(f"  Rejected:       {stats['rejected']}")
            if stats['oldest_timestamp']:
                from datetime import datetime, timezone
                oldest = datetime.fromtimestamp(stats['oldest_timestamp'], tz=timezone.utc)
                console.print(f"  Oldest entry:   {oldest.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        elif args.cache_action == "clear":
            count = cache_clear()
            logger.warning(f"[yellow]Cleared {count} cache entries.[/yellow]")
        elif args.cache_action == "prune":
            count = cache_prune()
            logger.info(f"[cyan]Pruned {count} expired cache entries.[/cyan]")


    elif args.command == "verify":
        _run_verify(args.ecosystem, args.package)


def _run_verify(ecosystem: str, package: str):
    """Download a package and verify its upstream provenance without installing."""
    from .signature_verifier import verify_pip_provenance, verify_npm_signatures, verify_cargo_checksum

    if ecosystem == "pip":
        mgr = PipManager()
        archive_paths, extract_dir = mgr.download(package, include_deps=False)
        try:
            for archive_path in archive_paths:
                verified, msg = verify_pip_provenance(package, archive_path)
                if verified:
                    console.print(f"[bold green]VERIFIED: {msg}[/bold green]")
                else:
                    console.print(f"[bold red]FAILED: {msg}[/bold red]")
        finally:
            mgr.cleanup(archive_paths, extract_dir)

    elif ecosystem == "npm":
        verified, msg = verify_npm_signatures(package)
        if verified:
            console.print(f"[bold green]VERIFIED: {msg}[/bold green]")
        else:
            console.print(f"[bold red]FAILED: {msg}[/bold red]")

    elif ecosystem == "cargo":
        mgr = CargoManager()
        archive_paths, extract_dir = mgr.download(package, include_deps=False)
        try:
            for archive_path in archive_paths:
                verified, msg = verify_cargo_checksum(package, archive_path)
                if verified:
                    console.print(f"[bold green]VERIFIED: {msg}[/bold green]")
                else:
                    console.print(f"[bold red]FAILED: {msg}[/bold red]")
        finally:
            mgr.cleanup(archive_paths, extract_dir)


if __name__ == "__main__":
    main()
