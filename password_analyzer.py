"""
Password Strength Analyzer
===========================
Analyzes password strength and provides detailed security recommendations.

Author: Abdullah Abdulaziz Almutairi
GitHub: github.com/xvxs37778-cloud

Usage:
    python password_analyzer.py
"""

import re
import math
import string


# ─────────────────────────────────────────────
#  Core Analysis
# ─────────────────────────────────────────────

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "111111", "123123",
    "admin", "letmein", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "football", "shadow",
    "superman", "michael", "password1", "iloveyou", "1234",
    "000000", "login", "hello", "charlie", "donald",
}

KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "123456789", "987654321",
    "qazwsx", "1qaz2wsx",
]


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?`~]', password):
        charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def check_password(password: str) -> dict:
    """Run all checks and return a full analysis report."""
    issues   = []
    tips     = []
    score    = 0

    # ── Length ──────────────────────────────
    length = len(password)
    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    elif length < 12:
        tips.append("Consider using 12+ characters for better security")
        score += 10
    elif length < 16:
        score += 20
    else:
        score += 30

    # ── Character variety ───────────────────
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?`~]', password))

    variety = sum([has_lower, has_upper, has_digit, has_special])

    if not has_lower:
        tips.append("Add lowercase letters (a–z)")
    if not has_upper:
        tips.append("Add uppercase letters (A–Z)")
    if not has_digit:
        tips.append("Add numbers (0–9)")
    if not has_special:
        tips.append("Add special characters (!@#$...)")

    score += variety * 10

    # ── Common passwords ────────────────────
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common passwords — avoid it!")
        score = max(0, score - 40)

    # ── Keyboard patterns ───────────────────
    pw_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower:
            issues.append(f"Contains keyboard pattern: '{pattern}'")
            score = max(0, score - 15)
            break

    # ── Repeated characters ──────────────────
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains 3+ repeated characters in a row (e.g. 'aaa')")
        score = max(0, score - 10)

    # ── Sequential numbers/letters ───────────
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in pw_lower or seq[i:i+4][::-1] in pw_lower:
                issues.append("Contains sequential characters (e.g. '1234' or 'abcd')")
                score = max(0, score - 10)
                break

    # ── Entropy bonus ────────────────────────
    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10

    # ── Cap score ────────────────────────────
    score = min(score, 100)

    # ── Strength label ───────────────────────
    if score < 20 or issues:
        strength = "WEAK"
        color    = "RED"
    elif score < 50:
        strength = "FAIR"
        color    = "YELLOW"
    elif score < 75:
        strength = "GOOD"
        color    = "CYAN"
    else:
        strength = "STRONG"
        color    = "GREEN"

    # ── Crack time estimate ──────────────────
    combinations = 2 ** entropy if entropy > 0 else 1
    guesses_per_second = 1_000_000_000  # 1 billion/sec (offline attack)
    seconds = combinations / guesses_per_second

    if seconds < 60:
        crack_time = f"{seconds:.1f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds/86400:.1f} days"
    elif seconds < 31536000 * 1000:
        crack_time = f"{seconds/31536000:.1f} years"
    else:
        crack_time = "centuries"

    return {
        "password"   : password,
        "score"      : score,
        "strength"   : strength,
        "color"      : color,
        "entropy"    : round(entropy, 2),
        "crack_time" : crack_time,
        "length"     : length,
        "has_lower"  : has_lower,
        "has_upper"  : has_upper,
        "has_digit"  : has_digit,
        "has_special": has_special,
        "issues"     : issues,
        "tips"       : tips,
    }


# ─────────────────────────────────────────────
#  Display
# ─────────────────────────────────────────────

COLORS = {
    "RED"   : "\033[91m",
    "YELLOW": "\033[93m",
    "CYAN"  : "\033[96m",
    "GREEN" : "\033[92m",
    "BOLD"  : "\033[1m",
    "RESET" : "\033[0m",
    "DIM"   : "\033[2m",
    "WHITE" : "\033[97m",
}


def colorize(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


def print_bar(score: int, color: str):
    filled = int(score / 5)        # 20 blocks total
    bar    = "█" * filled + "░" * (20 - filled)
    print(f"  [{colorize(bar, color)}] {colorize(str(score) + '/100', 'BOLD')}")


def print_checklist(result: dict):
    checks = [
        ("Lowercase letters",  result["has_lower"]),
        ("Uppercase letters",  result["has_upper"]),
        ("Numbers",            result["has_digit"]),
        ("Special characters", result["has_special"]),
        ("Length ≥ 12",        result["length"] >= 12),
        ("No common patterns", not result["issues"]),
    ]
    print()
    for label, passed in checks:
        icon = colorize("✔", "GREEN") if passed else colorize("✘", "RED")
        print(f"    {icon}  {label}")


def print_report(result: dict):
    w = colorize
    b = COLORS["BOLD"]
    r = COLORS["RESET"]

    print("\n" + "═" * 52)
    print(f"  {b}PASSWORD STRENGTH ANALYZER{r}  —  by Abdullah Almutairi")
    print("═" * 52)

    # Strength + bar
    print(f"\n  Strength : {w(result['strength'], result['color'])}")
    print_bar(result["score"], result["color"])

    # Stats
    print(f"\n  {b}Details{r}")
    print(f"    • Length     : {result['length']} characters")
    print(f"    • Entropy    : {result['entropy']} bits")
    print(f"    • Est. crack : {w(result['crack_time'], result['color'])}")

    # Checklist
    print(f"\n  {b}Checklist{r}")
    print_checklist(result)

    # Issues
    if result["issues"]:
        print(f"\n  {w('⚠  Issues Found', 'RED')}")
        for issue in result["issues"]:
            print(f"    • {issue}")

    # Tips
    if result["tips"]:
        print(f"\n  {w('💡  Suggestions', 'YELLOW')}")
        for tip in result["tips"]:
            print(f"    • {tip}")

    print("\n" + "═" * 52 + "\n")


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    print(colorize("\n  🔐 Password Strength Analyzer", "BOLD"))
    print(colorize("  Type 'quit' to exit\n", "DIM"))

    while True:
        try:
            password = input("  Enter password: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye!")
            break

        if password.lower() in ("quit", "exit", "q"):
            print("  Goodbye!")
            break

        if not password:
            print(colorize("  ⚠  Please enter a password.\n", "YELLOW"))
            continue

        result = check_password(password)
        print_report(result)


if __name__ == "__main__":
    main()
