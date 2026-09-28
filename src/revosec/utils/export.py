"""Export results to JSON, CSV, Markdown."""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Any
from rich.console import Console

console = Console()

REPORTS_DIR = Path.home() / ".revosec" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def export_json(data: Any, filename: str | None = None) -> Path:
    """Export data as pretty JSON."""
    if filename is None:
        filename = f"report_{_timestamp()}.json"
    path = REPORTS_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    console.print(f"[green]✓ JSON report saved:[/green] {path}")
    return path


def export_csv(rows: list[dict], filename: str | None = None) -> Path:
    """Export list of dicts as CSV."""
    if not rows:
        console.print("[yellow]No data to export.[/yellow]")
        return Path()
    if filename is None:
        filename = f"report_{_timestamp()}.csv"
    path = REPORTS_DIR / filename
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    console.print(f"[green]✓ CSV report saved:[/green] {path}")
    return path


def export_markdown(title: str, content: str, filename: str | None = None) -> Path:
    """Export markdown report."""
    if filename is None:
        filename = f"report_{_timestamp()}.md"
    path = REPORTS_DIR / filename
    md = f"# {title}\n\nGenerated: {datetime.now().isoformat()}\n\n{content}\n"
    path.write_text(md, encoding="utf-8")
    console.print(f"[green]✓ Markdown report saved:[/green] {path}")
    return path
