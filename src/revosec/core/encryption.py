"""Modern authenticated encryption suite using cryptography library.

Uses AES-256-GCM and ChaCha20-Poly1305 only.
Never implements custom crypto.
"""

import os
import base64
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from revosec.utils.logger import logger

console = Console()

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12  # Standard for GCM and ChaCha20-Poly1305
KEY_SIZE = 32   # 256-bit


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a strong key from password using Scrypt (memory-hard)."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,  # CPU/memory cost
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    password: str | None = None,
    algorithm: str = "aes-gcm",
) -> Path:
    """
    Encrypt a file with authenticated encryption.

    Args:
        input_path: Path to plaintext file
        output_path: Optional output path (default: input + .revosec)
        password: Encryption password (prompted if None)
        algorithm: 'aes-gcm' or 'chacha20'

    Returns:
        Path to encrypted file
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    if password is None:
        from getpass import getpass
        password = getpass("Enter encryption password: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            raise ValueError("Passwords do not match")

    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".revosec")
    else:
        output_path = Path(output_path)

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    if algorithm == "aes-gcm":
        aead = AESGCM(key)
    elif algorithm == "chacha20":
        aead = ChaCha20Poly1305(key)
    else:
        raise ValueError("Algorithm must be 'aes-gcm' or 'chacha20'")

    plaintext = input_path.read_bytes()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Encrypting...", total=None)
        ciphertext = aead.encrypt(nonce, plaintext, None)

    # Format: salt (16) + nonce (12) + ciphertext
    encrypted_data = salt + nonce + ciphertext
    output_path.write_bytes(encrypted_data)

    logger.info(f"Encrypted {input_path} → {output_path} using {algorithm}")
    console.print(f"[green]✓ Encrypted successfully:[/green] {output_path}")
    console.print(f"[dim]Algorithm: {algorithm} | Size: {len(encrypted_data)} bytes[/dim]")
    return output_path


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    password: str | None = None,
    algorithm: str = "aes-gcm",
) -> Path:
    """
    Decrypt a file encrypted by RevoSec.

    Args:
        input_path: Path to .revosec file
        output_path: Optional output path
        password: Decryption password
        algorithm: Must match encryption algorithm

    Returns:
        Path to decrypted file
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"File not found: {input_path}")

    if password is None:
        from getpass import getpass
        password = getpass("Enter decryption password: ")

    data = input_path.read_bytes()
    if len(data) < SALT_SIZE + NONCE_SIZE + 16:  # min auth tag
        raise ValueError("File too small or corrupted")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(password, salt)

    if algorithm == "aes-gcm":
        aead = AESGCM(key)
    elif algorithm == "chacha20":
        aead = ChaCha20Poly1305(key)
    else:
        raise ValueError("Algorithm must be 'aes-gcm' or 'chacha20'")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Decrypting...", total=None)
            plaintext = aead.decrypt(nonce, ciphertext, None)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e

    if output_path is None:
        # Remove .revosec suffix if present
        if input_path.suffix == ".revosec":
            output_path = input_path.with_suffix("")
        else:
            output_path = input_path.with_name(input_path.stem + "_decrypted" + input_path.suffix)
    else:
        output_path = Path(output_path)

    output_path.write_bytes(plaintext)
    logger.info(f"Decrypted {input_path} → {output_path}")
    console.print(f"[green]✓ Decrypted successfully:[/green] {output_path}")
    return output_path


def generate_key() -> str:
    """Generate a random 256-bit key (base64 encoded) for advanced use."""
    key = os.urandom(KEY_SIZE)
    return base64.urlsafe_b64encode(key).decode("ascii")
