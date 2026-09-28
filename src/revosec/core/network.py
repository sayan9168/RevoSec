"""Network analysis module - AUTHORIZED USE ONLY.

Includes:
- Local interface listing
- Authorized port scanning (requires explicit confirmation)
- Basic packet capture (with filter and confirmation)

All active operations require user confirmation and log the action.
"""

import socket
import ipaddress
from typing import List, Dict, Optional, Any
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from revosec.utils.logger import logger
from revosec.utils.export import export_json

console = Console()


def list_interfaces() -> List[Dict[str, Any]]:
    """List local network interfaces (passive, always safe)."""
    import psutil
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        info = {"name": name, "addresses": [], "is_up": False}
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                info["addresses"].append({
                    "ip": addr.address,
                    "netmask": addr.netmask,
                })
        if name in stats:
            info["is_up"] = stats[name].isup
            info["speed"] = stats[name].speed
        interfaces.append(info)

    table = Table(title="Network Interfaces", box=box.ROUNDED)
    table.add_column("Interface", style="cyan")
    table.add_column("Status")
    table.add_column("IPv4 Addresses")
    table.add_column("Speed")

    for iface in interfaces:
        status = "[green]UP[/green]" if iface["is_up"] else "[red]DOWN[/red]"
        ips = ", ".join(a["ip"] for a in iface["addresses"]) or "-"
        speed = f"{iface.get('speed', 0)} Mbps" if iface.get("speed") else "-"
        table.add_row(iface["name"], status, ips, speed)

    console.print(table)
    return interfaces


def _validate_target(target: str) -> bool:
    """Basic validation that target looks like IP or hostname."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Could be hostname
        if len(target) > 0 and all(c.isalnum() or c in ".-" for c in target):
            return True
    return False


def port_scan(
    target: str,
    ports: str = "1-1024",
    timeout: float = 1.0,
    require_confirm: bool = True,
) -> List[Dict[str, Any]]:
    """
    TCP port scanner for AUTHORIZED targets only.

    Requires explicit user confirmation before scanning.
    """
    if not _validate_target(target):
        console.print("[red]Invalid target format.[/red]")
        return []

    console.print(
        Panel_warning(
            f"You are about to scan: [bold]{target}[/bold]\n"
            f"Ports: {ports}\n\n"
            "Only scan systems you own or have explicit written authorization for."
        )
    )

    if require_confirm:
        if not Confirm.ask("[bold yellow]Do you have authorization to scan this target?[/bold yellow]"):
            console.print("[red]Scan aborted. Authorization required.[/red]")
            logger.warning(f"Port scan aborted by user for target {target}")
            return []

    logger.info(f"Authorized port scan started: target={target}, ports={ports}")

    # Parse ports
    port_list = _parse_ports(ports)
    open_ports = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {target}...", total=len(port_list))

        for port in port_list:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = _guess_service(port)
                        open_ports.append({
                            "port": port,
                            "state": "open",
                            "service": service,
                        })
                        console.print(f"[green]  ✓ Port {port}/tcp open[/green] ({service})")
            except socket.gaierror:
                console.print(f"[red]Hostname resolution failed for {target}[/red]")
                break
            except Exception:
                pass
            progress.advance(task)

    if open_ports:
        table = Table(title=f"Open Ports on {target}", box=box.ROUNDED)
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Likely Service")
        for p in open_ports:
            table.add_row(str(p["port"]), p["state"], p["service"])
        console.print(table)
    else:
        console.print("[yellow]No open ports found in the specified range.[/yellow]")

    logger.info(f"Port scan completed: {len(open_ports)} open ports on {target}")
    return open_ports


def _parse_ports(ports: str) -> List[int]:
    """Parse port range string like '22,80,443' or '1-1024'."""
    result = []
    for part in ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return sorted(set(result))


def _guess_service(port: int) -> str:
    """Simple common port to service mapping."""
    common = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
        445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-proxy", 27017: "mongodb",
    }
    return common.get(port, "unknown")


def Panel_warning(message: str):
    """Helper for warning panel."""
    return Panel(message, title="[bold red]⚠ AUTHORIZATION REQUIRED[/bold red]", border_style="red")
