"""Basic tests for encryption module."""

import tempfile
from pathlib import Path
from revosec.core.encryption import encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        plain = Path(tmp) / "test.txt"
        plain.write_text("Hello RevoSec secret data!", encoding="utf-8")

        enc = encrypt_file(plain, password="testpass123", algorithm="aes-gcm")
        assert enc.exists()
        assert enc.suffix == ".revosec" or "revosec" in str(enc)

        dec = Path(tmp) / "decrypted.txt"
        decrypt_file(enc, dec, password="testpass123", algorithm="aes-gcm")
        assert dec.read_text(encoding="utf-8") == "Hello RevoSec secret data!"
