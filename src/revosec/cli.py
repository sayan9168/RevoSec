"""
RevoSec CLI - Revolutionary Ethical Cybersecurity Toolkit
"""

import typer
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt

from revosec.utils.banner import print_banner, print_module_header
from revosec.utils.logger import logger
from revosec.core import encryption, password, audit, network, hashing, integrity

app = typer.Typer(
    name="revosec",
    help="Revolutionary Ethical Cybersecurity Toolkit. Authorized use only.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """RevoSec - Revolutionary Ethical Cybersecurity Toolkit."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[bold]Available commands:[/bold]\n")
        console.print("  [cyan]encrypt[/cyan]     Encrypt a file (AES-GCM / ChaCha20)")
        console.print("  [cyan]decrypt[/cyan]     Decrypt a RevoSec encrypted file")
        console.print("  [cyan]password[/cyan]    Generate & analyze strong passwords")
        console.print("  [cyan]audit[/cyan]       Local system security audit")
        console.print("  [cyan]interfaces[/cyan]  List network interfaces")
        console.print("  [cyan]scan[/cyan]        Authorized TCP port scan")
        console.print("  [cyan]hash[/cyan]        Hash files / strings / verify / identify")
        console.print("  [cyan]fim[/cyan]         File Integrity Monitoring (baseline + check)")
        console.print("  [cyan]version[/cyan]     Show version")
        console.print("\n[dim]Use: revosec <command> --help for details[/dim]\n")


@app.command()
def encrypt(
    file: str = typer.Argument(..., help="File to encrypt"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path"),
    algorithm: str = typer.Option("aes-gcm", "--algo", "-a", help="aes-gcm or chacha20"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password (prompt if omitted)"),
):
    """Encrypt a file with modern authenticated encryption."""
    print_module_header("File Encryption", "AES-256-GCM or ChaCha20-Poly1305 + Scrypt KDF")
    try:
        encryption.encrypt_file(file, output, password, algorithm)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def decrypt(
    file: str = typer.Argument(..., help="Encrypted .revosec file"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path"),
    algorithm: str = typer.Option("aes-gcm", "--algo", "-a", help="Must match encryption algo"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password (prompt if omitted)"),
):
    """Decrypt a file encrypted by RevoSec."""
    print_module_header("File Decryption")
    try:
        encryption.decrypt_file(file, output, password, algorithm)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def password(
    length: int = typer.Option(20, "--length", "-l", help="Password length (min 8)"),
    count: int = typer.Option(1, "--count", "-c", help="How many passwords to generate"),
    no_symbols: bool = typer.Option(False, "--no-symbols", help="Exclude symbols"),
    analyze: Optional[str] = typer.Option(None, "--analyze", "-a", help="Analyze an existing password"),
):
    """Generate strong passwords or analyze password strength."""
    print_module_header("Password Tools", "Cryptographically secure generation + strength analysis")

    if analyze:
        password.print_strength_report(analyze)
        return

    for i in range(count):
        pwd = password.generate_password(
            length=length,
            use_symbols=not no_symbols,
        )
        console.print(f"[bold green]{pwd}[/bold green]")
        if count == 1:
            console.print()
            password.print_strength_report(pwd)


@app.command()
def audit(
    export: bool = typer.Option(False, "--export", "-e", help="Export report to ~/.revosec/reports/"),
):
    """Run a local system security audit (defensive)."""
    print_module_header("System Security Audit", "Local host only — no external scanning")
    try:
        audit.run_full_audit(export=export)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        logger.exception("Audit failed")
        raise typer.Exit(1)


@app.command()
def interfaces():
    """List local network interfaces (passive)."""
    print_module_header("Network Interfaces")
    network.list_interfaces()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or hostname (AUTHORIZED only)"),
    ports: str = typer.Option("1-1024", "--ports", "-p", help="Port range (e.g. 22,80,443 or 1-1000)"),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Timeout per port in seconds"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation (still logs)"),
):
    """
    TCP port scan — AUTHORIZED TARGETS ONLY.

    Requires explicit confirmation. Unauthorized scanning is illegal.
    """
    print_module_header("Authorized Port Scanner", "Only scan systems you own or have written permission for")
    try:
        results = network.port_scan(target, ports, timeout, require_confirm=not yes)
        if results:
            from revosec.utils.export import export_json
            export_json(
                {"target": target, "open_ports": results},
                f"scan_{target.replace('.', '_')}.json",
            )
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def hash(
    target: Optional[str] = typer.Argument(None, help="File path or string to hash"),
    algorithm: str = typer.Option("sha256", "--algo", "-a", help="md5, sha1, sha256, sha512, blake2b, blake2s"),
    verify: Optional[str] = typer.Option(None, "--verify", "-v", help="Expected hash to verify against"),
    identify: Optional[str] = typer.Option(None, "--identify", "-i", help="Identify possible algorithm of a hash"),
    multi: bool = typer.Option(False, "--multi", "-m", help="Show multiple common hashes for a file"),
    text: bool = typer.Option(False, "--text", "-t", help="Treat target as string instead of file"),
):
    """Hash files/strings, verify integrity, or identify hash type."""
    print_module_header("Hash Tools", "Generate • Verify • Identify")

    if identify:
        candidates = hashing.identify_hash(identify)
        console.print(f"[cyan]Hash:[/cyan] {identify}")
        console.print(f"[cyan]Possible algorithms:[/cyan] {', '.join(candidates)}")
        return

    if not target:
        console.print("[red]Provide a file path or string (use --text for strings)[/red]")
        raise typer.Exit(1)

    try:
        if multi and not text:
            hashing.print_hash_report(target)
        elif text:
            digest = hashing.hash_string(target, algorithm)
            console.print(f"[green]{algorithm.upper()}:[/green] {digest}")
        elif verify:
            hashing.verify_file(target, verify, algorithm)
        else:
            digest = hashing.hash_file(target, algorithm)
            console.print(f"[green]{algorithm.upper()}:[/green] {digest}")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def fim(
    action: str = typer.Argument(..., help="create | check | list"),
    path: Optional[str] = typer.Argument(None, help="Directory path (for create)"),
    name: str = typer.Option("default", "--name", "-n", help="Baseline name"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="Scan subdirectories"),
    show_ok: bool = typer.Option(False, "--show-ok", help="Also show unchanged files"),
):
    """
    File Integrity Monitoring.

    Examples:
      revosec fim create /etc --name system
      revosec fim check --name system
      revosec fim list
    """
    print_module_header("File Integrity Monitor", "Baseline → Detect changes")

    try:
        if action == "create":
            if not path:
                console.print("[red]Directory path required for 'create'[/red]")
                raise typer.Exit(1)
            integrity.create_baseline(path, name=name, recursive=recursive)
        elif action == "check":
            integrity.check_integrity(name=name, show_ok=show_ok)
        elif action == "list":
            integrity.list_baselines()
        else:
            console.print("[red]Action must be: create | check | list[/red]")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        logger.exception("FIM failed")
        raise typer.Exit(1)


@app.command()
def version():
    """Show RevoSec version."""
    from revosec import __version__
    console.print(f"[bold]RevoSec[/bold] v{__version__}")
    console.print("Revolutionary Ethical Cybersecurity Toolkit")
    console.print("https://github.com/sayan9168/RevoSec")


if __name__ == "__main__":
    app()
