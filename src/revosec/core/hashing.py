"""Hash generation, verification and identification tools.

Educational / defensive use only.
Supports: MD5, SHA1, SHA256, SHA512, BLAKE2b, BLAKE2s
"""

import hashlib
import hmac
from pathlib import Path
from typing import Dict, Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from revosec.utils.logger import logger

console = Console()

SUPPORTED = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    """Compute hash of a file (streaming for large files)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    algo = algorithm.lower()
    if algo not in SUPPORTED:
        raise ValueError(f"Unsupported algorithm. Choose from: {', '.join(SUPPORTED)}")

    h = SUPPORTED[algo]()
    with open(path, "rb") as f:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Hashing with {algo.upper()}...", total=path.stat().st_size)
            while chunk := f.read(8192):
                h.update(chunk)
                progress.advance(task, len(chunk))

    digest = h.hexdigest()
    logger.info(f"Hashed {path} with {algo}: {digest[:16]}...")
    return digest


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """Hash a string."""
    algo = algorithm.lower()
    if algo not in SUPPORTED:
        raise ValueError(f"Unsupported algorithm. Choose from: {', '.join(SUPPORTED)}")
    return SUPPORTED[algo](text.encode("utf-8")).hexdigest()


def verify_file(path: str | Path, expected_hash: str, algorithm: str = "sha256") -> bool:
    """Verify file against expected hash."""
    actual = hash_file(path, algorithm)
    match = hmac.compare_digest(actual.lower(), expected_hash.lower())
    if match:
        console.print(f"[green]✓ Hash match![/green] {algorithm.upper()} verified.")
    else:
        console.print(f"[red]✗ Hash mismatch![/red]")
        console.print(f"  Expected : {expected_hash}")
        console.print(f"  Actual   : {actual}")
    return match


def identify_hash(hash_str: str) -> List[str]:
    """Guess possible algorithms based on hash length and charset."""
    h = hash_str.strip().lower()
    length = len(h)
    candidates = []

    # Basic length heuristics
    if length == 32 and all(c in "0123456789abcdef" for c in h):
        candidates.append("MD5")
    if length == 40 and all(c in "0123456789abcdef" for c in h):
        candidates.append("SHA1")
    if length == 64 and all(c in "0123456789abcdef" for c in h):
        candidates.extend(["SHA256", "BLAKE2s"])
    if length == 128 and all(c in "0123456789abcdef" for c in h):
        candidates.extend(["SHA512", "BLAKE2b"])

    return candidates or ["Unknown / Custom"]


def print_hash_report(path: str | Path, algorithms: Optional[List[str]] = None) -> Dict[str, str]:
    """Compute multiple hashes and show nice table."""
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "sha512"]

    results = {}
    table = Table(title=f"Hash Report — {Path(path).name}", box=box.ROUNDED)
    table.add_column("Algorithm", style="cyan")
    table.add_column("Digest")

    for algo in algorithms:
        try:
            digest = hash_file(path, algo)
            results[algo] = digest
            table.add_row(algo.upper(), digest)
        except Exception as e:
            table.add_row(algo.upper(), f"[red]Error: {e}[/red]")

    console.print(table)
    return results
