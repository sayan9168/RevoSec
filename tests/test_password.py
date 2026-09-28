"""Basic tests for password module."""

from revosec.core.password import generate_password, analyze_strength


def test_generate_password_length():
    pwd = generate_password(length=16)
    assert len(pwd) == 16


def test_generate_password_variety():
    pwd = generate_password(length=20)
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)


def test_analyze_strength():
    result = analyze_strength("Weak1")
    assert "level" in result
    assert result["score"] >= 0

    strong = analyze_strength("Xk9$mP2vL8qR5nW3jH7!")
    assert strong["level"] in ("Strong", "Excellent")
