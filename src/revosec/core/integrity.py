"""File Integrity Monitoring (FIM) using hashes + watchdog.

Creates a baseline of file hashes and can detect changes.
Defensive / authorized use only.
"""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import box

from revosec.core.hashing import hash_file
from revosec.utils.logger import logger
from revosec.utils.export import export_json

console = Console()

BASELINE_DIR = Path.home() / ".revosec" / "baselines"
BASELINE_DIR.mkdir(parents=True, exist_ok=True)


def create_baseline(
    directory: str | Path,
    name: str = "default",
    recursive: bool = True,
    extensions: Optional[List[str]] = None,
) -> Path:
    """
    Create a hash baseline of all files in a directory.
    """
    directory = Path(directory).resolve()
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    console.print(f"[cyan]Creating baseline '{name}' for {directory}...[/cyan]")

    files: Dict[str, Dict] = {}
    count = 0

    pattern = "**/*" if recursive else "*"
    for path in directory.glob(pattern):
        if not path.is_file():
            continue
        if extensions and path.suffix.lower() not in extensions:
            continue

        try:
            rel = str(path.relative_to(directory))
            digest = hash_file(path, "sha256")
            stat = path.stat()
            files[rel] = {
                "sha256": digest,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
            count += 1
            console.print(f"  [dim]✓ {rel}[/dim]")
        except Exception as e:
            console.print(f"  [yellow]Skip {path}: {e}[/yellow]")

    baseline = {
        "name": name,
        "root": str(directory),
        "created": datetime.now().isoformat(),
        "file_count": count,
        "files": files,
    }

    out_path = BASELINE_DIR / f"{name}.json"
    out_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    console.print(Panel(
        f"[green]Baseline created[/green]\n"
        f"Name   : {name}\n"
        f"Files  : {count}\n"
        f"Saved  : {out_path}",
        title="File Integrity Baseline",
        border_style="green",
    ))
    logger.info(f"Baseline '{name}' created with {count} files")
    return out_path


def check_integrity(name: str = "default", show_ok: bool = False) -> Dict:
    """Compare current files against a saved baseline."""
    baseline_path = BASELINE_DIR / f"{name}.json"
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline not found: {baseline_path}\nRun 'revosec fim create' first.")

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    root = Path(baseline["root"])
    expected = baseline["files"]

    console.print(f"[cyan]Checking integrity against baseline '{name}'...[/cyan]\n")

    current: Dict[str, Dict] = {}
    for rel, meta in expected.items():
        path = root / rel
        if path.exists() and path.is_file():
            try:
                digest = hash_file(path, "sha256")
                current[rel] = {"sha256": digest, "size": path.stat().st_size}
            except Exception:
                current[rel] = {"sha256": None, "size": 0}

    added = []
    modified = []
    deleted = []
    ok = []

    for rel, meta in expected.items():
        if rel not in current or current[rel]["sha256"] is None:
            deleted.append(rel)
        elif current[rel]["sha256"] != meta["sha256"]:
            modified.append({
                "file": rel,
                "old": meta["sha256"][:16] + "...",
                "new": current[rel]["sha256"][:16] + "...",
            })
        else:
            ok.append(rel)

    if root.exists():
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    rel = str(path.relative_to(root))
                    if rel not in expected:
                        added.append(rel)
                except ValueError:
                    pass

    table = Table(title=f"Integrity Check — {name}", box=box.ROUNDED)
    table.add_column("Status", style="bold")
    table.add_column("Count")
    table.add_row("[green]Unchanged[/green]", str(len(ok)))
    table.add_row("[yellow]Modified[/yellow]", str(len(modified)))
    table.add_row("[red]Deleted[/red]", str(len(deleted)))
    table.add_row("[blue]Added[/blue]", str(len(added)))
    console.print(table)

    if modified:
        console.print("\n[bold yellow]Modified files:[/bold yellow]")
        for m in modified:
            console.print(f"  • {m['file']}  ({m['old']} → {m['new']})")

    if deleted:
        console.print("\n[bold red]Deleted files:[/bold red]")
        for d in deleted:
            console.print(f"  • {d}")

    if added:
        console.print("\n[bold blue]New files:[/bold blue]")
        for a in added[:20]:
            console.print(f"  • {a}")
        if len(added) > 20:
            console.print(f"  ... and {len(added)-20} more")

    if show_ok and ok:
        console.print(f"\n[dim]{len(ok)} files unchanged.[/dim]")

    result = {
        "baseline": name,
        "timestamp": datetime.now().isoformat(),
        "unchanged": len(ok),
        "modified": modified,
        "deleted": deleted,
        "added": added,
    }

    if modified or deleted or added:
        export_json(result, f"integrity_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    logger.info(f"Integrity check '{name}': {len(modified)} modified, {len(deleted)} deleted, {len(added)} added")
    return result


def list_baselines() -> None:
    """List all saved baselines."""
    baselines = list(BASELINE_DIR.glob("*.json"))
    if not baselines:
        console.print("[yellow]No baselines found. Create one with: revosec fim create <dir>[/yellow]")
        return

    table = Table(title="Saved Baselines", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Files")
    table.add_column("Created")
    table.add_column("Root")

    for b in sorted(baselines):
        try:
            data = json.loads(b.read_text(encoding="utf-8"))
            table.add_row(
                data.get("name", b.stem),
                str(data.get("file_count", "?")),
                data.get("created", "?")[:19],
                data.get("root", "?")[:50],
            )
        except Exception:
            table.add_row(b.stem, "?", "?", "?")

    console.print(table)


def watch_directory(
    directory: str | Path,
    recursive: bool = True,
    duration: Optional[int] = None,
) -> None:
    """
    Real-time File Integrity Monitoring using watchdog.
    Prints events as files are created, modified, or deleted.
    Press Ctrl+C to stop.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        console.print("[red]watchdog not installed. Run: pip install watchdog[/red]")
        return

    directory = Path(directory).resolve()
    if not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    class FIMHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                console.print(f"[green]CREATED[/green]  {event.src_path}")
                logger.info(f"FIM CREATED: {event.src_path}")

        def on_modified(self, event):
            if not event.is_directory:
                console.print(f"[yellow]MODIFIED[/yellow] {event.src_path}")
                logger.info(f"FIM MODIFIED: {event.src_path}")

        def on_deleted(self, event):
            if not event.is_directory:
                console.print(f"[red]DELETED[/red]  {event.src_path}")
                logger.info(f"FIM DELETED: {event.src_path}")

        def on_moved(self, event):
            if not event.is_directory:
                console.print(f"[blue]MOVED[/blue]    {event.src_path} → {event.dest_path}")
                logger.info(f"FIM MOVED: {event.src_path} → {event.dest_path}")

    console.print(Panel(
        f"[bold]Watching:[/bold] {directory}\n"
        f"Recursive: {recursive}\n"
        f"Press [bold]Ctrl+C[/bold] to stop.",
        title="Real-time FIM",
        border_style="cyan",
    ))

    event_handler = FIMHandler()
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=recursive)
    observer.start()

    try:
        if duration:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[cyan]Stopping watcher...[/cyan]")
    finally:
        observer.stop()
        observer.join()
        console.print("[green]Watcher stopped.[/green]")
