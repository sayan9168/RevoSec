"""Password generation and strength analysis."""

import secrets
import string
import re
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def generate_password(
    length: int = 20,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """
    Generate a cryptographically secure password.

    Uses secrets module (not random) for security.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8")

    chars = ""
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if exclude_ambiguous:
        # Remove easily confused characters
        for c in "0O1lI|":
            chars = chars.replace(c, "")

    if not chars:
        raise ValueError("At least one character set must be enabled")

    # Ensure at least one of each selected type
    password = []
    if use_lowercase:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))

    remaining = length - len(password)
    password.extend(secrets.choice(chars) for _ in range(remaining))

    # Shuffle
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list)


def analyze_strength(password: str) -> Dict:
    """
    Analyze password strength with detailed feedback.

    Returns a dict with score, level, feedback, and entropy estimate.
    """
    score = 0
    feedback: List[str] = []
    length = len(password)

    # Length
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Too short (minimum 8, recommended 16+)")

    # Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety

    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add digits")
    if not has_symbol:
        feedback.append("Add symbols")

    # Common patterns
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeated characters")
    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
        score -= 1
        feedback.append("Avoid sequential patterns")

    # Entropy estimate (rough)
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 20
    entropy = length * (charset_size.bit_length() if charset_size else 0)  # approx log2

    # Level
    if score >= 8:
        level = "Excellent"
        color = "green"
    elif score >= 6:
        level = "Strong"
        color = "bright_green"
    elif score >= 4:
        level = "Moderate"
        color = "yellow"
    elif score >= 2:
        level = "Weak"
        color = "orange1"
    else:
        level = "Very Weak"
        color = "red"

    return {
        "score": max(0, score),
        "level": level,
        "color": color,
        "length": length,
        "entropy_bits_approx": entropy,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
        "feedback": feedback or ["Looks good!"],
    }


def print_strength_report(password: str) -> None:
    """Pretty print strength analysis."""
    result = analyze_strength(password)

    table = Table(title="Password Strength Analysis", box=box.ROUNDED, show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value")

    table.add_row("Strength", f"[{result['color']}]{result['level']}[/{result['color']}]")
    table.add_row("Score", f"{result['score']}/10+")
    table.add_row("Length", str(result["length"]))
    table.add_row("Approx Entropy", f"~{result['entropy_bits_approx']} bits")
    table.add_row("Lowercase", "✓" if result["has_lowercase"] else "✗")
    table.add_row("Uppercase", "✓" if result["has_uppercase"] else "✗")
    table.add_row("Digits", "✓" if result["has_digits"] else "✗")
    table.add_row("Symbols", "✓" if result["has_symbols"] else "✗")

    console.print(table)

    if result["feedback"]:
        feedback_text = "\n".join(f"• {f}" for f in result["feedback"])
        console.print(Panel(feedback_text, title="Recommendations", border_style="yellow"))
