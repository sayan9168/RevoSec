"""ASCII banner and branding for RevoSec."""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""
[bold red]
██████╗ ███████╗██╗   ██╗ ██████╗ ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██║   ██║██╔═══██╗██╔════╝██╔════╝██╔═══██╗
██████╔╝█████╗  ██║   ██║██║   ██║███████╗█████╗  ██║   ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝██║   ██║╚════██║██╔══╝  ██║   ██║
██║  ██║███████╗ ╚████╔╝ ╚██████╔╝███████║███████╗╚██████╔╝
╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚════╝ ╚══════╝╚══════╝ ╚═════╝
[/bold red]
"""

TAGLINE = "[bold cyan]Revolutionary Ethical Cybersecurity Toolkit[/bold cyan]"
VERSION = "[dim]v1.0.0 | Production Grade | Authorized Use Only[/dim]"


def print_banner() -> None:
    """Print the full RevoSec banner with warning."""
    console.print(BANNER)
    console.print(TAGLINE, justify="center")
    console.print(VERSION, justify="center")
    console.print()
    console.print(
        Panel(
            "[bold yellow]⚠ ETHICAL USE ONLY[/bold yellow]\n\n"
            "This tool is designed for:\n"
            "• Authorized penetration testing\n"
            "• Defensive security research\n"
            "• Educational purposes\n"
            "• Systems you own or have explicit written permission to test\n\n"
            "[bold red]Unauthorized scanning, access, or attacks are ILLEGAL.[/bold red]",
            title="[bold red]LEGAL DISCLAIMER[/bold red]",
            border_style="red",
            box=box.DOUBLE,
        )
    )
    console.print()


def print_module_header(title: str, description: str = "") -> None:
    """Print a consistent module header."""
    text = Text(title, style="bold magenta")
    if description:
        text.append(f"\n{description}", style="dim")
    console.print(Panel(text, border_style="magenta", box=box.ROUNDED))
