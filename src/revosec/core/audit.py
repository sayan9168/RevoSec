"""Local system security audit module.

Collects defensive information about the host system.
No network scanning or external probes.
"""

import platform
import socket
import psutil
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from revosec.utils.logger import logger
from revosec.utils.export import export_json, export_markdown

console = Console()


def get_system_info() -> Dict[str, Any]:
    """Collect basic system information."""
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
    }


def get_cpu_info() -> Dict[str, Any]:
    """CPU usage and details."""
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
    }


def get_memory_info() -> Dict[str, Any]:
    """Memory statistics."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_gb": round(mem.total / (1024**3), 2),
        "available_gb": round(mem.available / (1024**3), 2),
        "used_percent": mem.percent,
        "swap_total_gb": round(swap.total / (1024**3), 2),
        "swap_used_percent": swap.percent,
    }


def get_disk_info() -> List[Dict[str, Any]]:
    """Disk partitions and usage."""
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent": usage.percent,
            })
        except PermissionError:
            continue
    return disks


def get_network_interfaces() -> List[Dict[str, Any]]:
    """Local network interfaces (no scanning)."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        iface = {"name": name, "addresses": []}
        for addr in addr_list:
            iface["addresses"].append({
                "family": str(addr.family),
                "address": addr.address,
                "netmask": addr.netmask,
            })
        if name in stats:
            iface["isup"] = stats[name].isup
            iface["speed_mbps"] = stats[name].speed
        interfaces.append(iface)
    return interfaces


def get_listening_ports() -> List[Dict[str, Any]]:
    """List listening TCP/UDP ports on localhost (defensive view)."""
    ports = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN":
            ports.append({
                "pid": conn.pid,
                "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "status": conn.status,
            })
    return ports


def get_running_processes(limit: int = 20) -> List[Dict[str, Any]]:
    """Top processes by memory (defensive overview)."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_percent", "cpu_percent", "status"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "user": info["username"],
                "memory_percent": round(info["memory_percent"] or 0, 2),
                "cpu_percent": round(info["cpu_percent"] or 0, 2),
                "status": info["status"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Sort by memory
    procs.sort(key=lambda x: x["memory_percent"], reverse=True)
    return procs[:limit]


def run_full_audit(export: bool = False) -> Dict[str, Any]:
    """Run complete local system audit and optionally export."""
    console.print("[bold cyan]Running local system security audit...[/bold cyan]\n")

    report = {
        "timestamp": datetime.now().isoformat(),
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disks": get_disk_info(),
        "interfaces": get_network_interfaces(),
        "listening_ports": get_listening_ports(),
        "top_processes": get_running_processes(),
    }

    # Pretty print summary
    sys_info = report["system"]
    console.print(Panel(
        f"[bold]Hostname:[/bold] {sys_info['hostname']}\n"
        f"[bold]OS:[/bold] {sys_info['platform']} {sys_info['platform_release']}\n"
        f"[bold]Arch:[/bold] {sys_info['architecture']}\n"
        f"[bold]Boot:[/bold] {sys_info['boot_time']}",
        title="System Overview",
        border_style="cyan",
    ))

    mem = report["memory"]
    console.print(Panel(
        f"Total: {mem['total_gb']} GB | Available: {mem['available_gb']} GB | Used: {mem['used_percent']}%",
        title="Memory",
        border_style="green",
    ))

    # Listening ports table
    ports = report["listening_ports"]
    if ports:
        table = Table(title="Listening Ports (Local)", box=box.SIMPLE)
        table.add_column("PID", style="dim")
        table.add_column("Proto")
        table.add_column("Address")
        table.add_column("Status")
        for p in ports[:15]:
            table.add_row(
                str(p["pid"] or "-"),
                p["type"],
                p["local_address"] or "-",
                p["status"],
            )
        console.print(table)
        if len(ports) > 15:
            console.print(f"[dim]... and {len(ports)-15} more[/dim]")

    logger.info("Local system audit completed")

    if export:
        export_json(report, f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        # Markdown summary
        md_content = f"""## System
- Hostname: {sys_info['hostname']}
- OS: {sys_info['platform']} {sys_info['platform_release']}
- Architecture: {sys_info['architecture']}

## Memory
- Total: {mem['total_gb']} GB
- Used: {mem['used_percent']}%

## Listening Ports
{len(ports)} ports in LISTEN state
"""
        export_markdown("RevoSec System Audit", md_content)

    return report
