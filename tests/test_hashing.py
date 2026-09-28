"""Tests for hashing module."""

from revosec.core.hashing import hash_string, identify_hash


def test_hash_string_sha256():
    result = hash_string("hello", "sha256")
    assert len(result) == 64
    assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_string_md5():
    result = hash_string("hello", "md5")
    assert len(result) == 32


def test_identify_hash_md5():
    candidates = identify_hash("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in candidates


def test_identify_hash_sha256():
    candidates = identify_hash("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    assert "SHA256" in candidates or "BLAKE2s" in candidates
