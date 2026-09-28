"""Secure Vault - Encrypted notes and secrets storage.

Uses the same AES-GCM encryption as the main encryption module.
Vault stored in ~/.revosec/vault/
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from getpass import getpass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from revosec.core.encryption import encrypt_file, decrypt_file, derive_key
from revosec.utils.logger import logger

console = Console()

VAULT_DIR = Path.home() / ".revosec" / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)
VAULT_INDEX = VAULT_DIR / "index.json"


def _load_index() -> Dict:
    if VAULT_INDEX.exists():
        try:
            return json.loads(VAULT_INDEX.read_text(encoding="utf-8"))
        except Exception:
            return {"notes": {}}
    return {"notes": {}}


def _save_index(index: Dict) -> None:
    VAULT_INDEX.write_text(json.dumps(index, indent=2), encoding="utf-8")


def add_note(title: str, content: str, password: Optional[str] = None) -> None:
    """Add an encrypted note to the vault."""
    if password is None:
        password = getpass("Vault password: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            console.print("[red]Passwords do not match[/red]")
            return

    note_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + title.replace(" ", "_")[:20]
    plain_path = VAULT_DIR / f"{note_id}.txt"
    enc_path = VAULT_DIR / f"{note_id}.revosec"

    plain_path.write_text(content, encoding="utf-8")
    try:
        encrypt_file(plain_path, enc_path, password=password, algorithm="aes-gcm")
        plain_path.unlink(missing_ok=True)

        index = _load_index()
        index["notes"][note_id] = {
            "title": title,
            "created": datetime.now().isoformat(),
            "file": str(enc_path.name),
        }
        _save_index(index)
        console.print(f"[green]✓ Note '{title}' saved to vault[/green]")
        logger.info(f"Vault note added: {title}")
    except Exception as e:
        plain_path.unlink(missing_ok=True)
        console.print(f"[red]Failed to encrypt note: {e}[/red]")


def list_notes() -> None:
    """List all notes in the vault."""
    index = _load_index()
    notes = index.get("notes", {})
    if not notes:
        console.print("[yellow]Vault is empty. Add a note with: revosec vault add[/yellow]")
        return

    table = Table(title="Secure Vault Notes", box=box.ROUNDED)
    table.add_column("ID", style="dim")
    table.add_column("Title", style="cyan")
    table.add_column("Created")

    for nid, meta in sorted(notes.items(), key=lambda x: x[1]["created"], reverse=True):
        table.add_row(nid[:16] + "...", meta["title"], meta["created"][:19])

    console.print(table)


def read_note(note_id: str, password: Optional[str] = None) -> None:
    """Decrypt and display a note."""
    index = _load_index()
    notes = index.get("notes", {})

    # Allow partial ID match
    matches = [k for k in notes if k.startswith(note_id) or note_id in k]
    if not matches:
        console.print(f"[red]Note not found: {note_id}[/red]")
        return
    if len(matches) > 1:
        console.print("[yellow]Multiple matches, be more specific:[/yellow]")
        for m in matches:
            console.print(f"  {m}")
        return

    nid = matches[0]
    meta = notes[nid]
    enc_path = VAULT_DIR / meta["file"]

    if not enc_path.exists():
        console.print("[red]Encrypted file missing[/red]")
        return

    if password is None:
        password = getpass("Vault password: ")

    tmp_path = VAULT_DIR / f"tmp_{nid}.txt"
    try:
        decrypt_file(enc_path, tmp_path, password=password, algorithm="aes-gcm")
        content = tmp_path.read_text(encoding="utf-8")
        tmp_path.unlink(missing_ok=True)

        console.print(Panel(
            content,
            title=f"[bold]{meta['title']}[/bold]",
            border_style="green",
            subtitle=f"Created: {meta['created'][:19]}",
        ))
    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        console.print(f"[red]Decryption failed: {e}[/red]")


def delete_note(note_id: str) -> None:
    """Delete a note from the vault."""
    index = _load_index()
    notes = index.get("notes", {})
    matches = [k for k in notes if k.startswith(note_id) or note_id in k]
    if not matches:
        console.print(f"[red]Note not found: {note_id}[/red]")
        return
    if len(matches) > 1:
        console.print("[yellow]Multiple matches:[/yellow]")
        for m in matches:
            console.print(f"  {m}")
        return

    nid = matches[0]
    if not Confirm.ask(f"Delete note '{notes[nid]['title']}'?"):
        return

    enc_path = VAULT_DIR / notes[nid]["file"]
    enc_path.unlink(missing_ok=True)
    del notes[nid]
    _save_index(index)
    console.print("[green]✓ Note deleted[/green]")
    logger.info(f"Vault note deleted: {nid}")
