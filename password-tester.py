import argparse
import re
import secrets
import string
import sys
from random import SystemRandom
from typing import Dict, List

SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
PATTERNS = {
    "uppercase": re.compile(r"[A-Z]"),
    "lowercase": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r"[{}]".format(re.escape(SPECIAL_CHARACTERS))),
}
COMMON_PATTERNS = [
    "password", "1234", "qwerty", "admin", "letmein", "welcome", "abc123", "secret",
    "iloveyou", "trustno1", "dragon", "monkey", "login", "passw0rd",
]

STRONG_LENGTH = 12
DEFAULT_GENERATE_LENGTH = 16
RNG = SystemRandom()


def evaluate_password(password: str) -> Dict[str, object]:
    """Evaluate password strength and return structured feedback."""
    password = password or ""
    feedback: List[str] = []
    score = 0
    categories = {}
    length = len(password)

    if length >= STRONG_LENGTH:
        score += 2
    elif length >= 8:
        score += 1
        feedback.append(f"Use at least {STRONG_LENGTH} characters for strong passwords.")
    else:
        feedback.append(f"Password is too short (use at least {STRONG_LENGTH} characters).")

    for name, pattern in PATTERNS.items():
        found = bool(pattern.search(password))
        categories[name] = found
        if found:
            score += 1
        else:
            if name == "special":
                feedback.append("Add special characters.")
            elif name == "uppercase":
                feedback.append("Add uppercase letters.")
            elif name == "lowercase":
                feedback.append("Add lowercase letters.")
            elif name == "digit":
                feedback.append("Add numbers.")

    lowered = password.lower()
    if any(common in lowered for common in COMMON_PATTERNS):
        feedback.append("Avoid common words, simple sequences, or repeated patterns.")
        score = min(score, 2)

    if length >= STRONG_LENGTH and all(categories.values()) and score >= 5:
        strength = "Strong"
    elif score >= 4:
        strength = "Moderate"
    else:
        strength = "Weak"

    if strength == "Weak" and not feedback:
        feedback.append("Use a longer passphrase with mixed character types.")

    return {
        "strength": strength,
        "score": score,
        "length": length,
        "categories": categories,
        "feedback": feedback,
    }


def generate_strong_password(length: int = DEFAULT_GENERATE_LENGTH) -> str:
    """Generate a password with at least one uppercase, lowercase, digit, and special character."""
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    required_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(SPECIAL_CHARACTERS),
    ]
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARACTERS
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required_chars))]
    password_chars = required_chars + remaining
    RNG.shuffle(password_chars)
    return "".join(password_chars)


def format_evaluation(result: Dict[str, object]) -> str:
    lines = [
        f"Strength: {result['strength']}",
        f"Score: {result['score']} / 6",
        f"Length: {result['length']}",
    ]
    categories = result["categories"]
    lines.append(
        "Categories: " + ", ".join(
            f"{name}={'yes' if ok else 'no'}" for name, ok in categories.items()
        )
    )
    if result["feedback"]:
        lines.append("Suggestions:")
        for item in result["feedback"]:
            lines.append(f" - {item}")
    return "\n".join(lines)


def safe_input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def interactive_mode() -> int:
    print("Password Tester Interactive Mode")
    print("  [e] Evaluate a password")
    print("  [g] Generate a strong password")
    print("  [q] Quit")
    while True:
        choice = safe_input("\nChoose an action [e/g/q]: ").strip().lower()
        if not choice or choice.startswith("q"):
            print("Bye.")
            return 0
        if choice.startswith("e"):
            password = safe_input("Enter password to evaluate: ")
            if not password:
                print("No password entered.")
                continue
            result = evaluate_password(password)
            print(format_evaluation(result))
            if result["strength"] != "Strong":
                print("Generated suggestion:", generate_strong_password())
            continue
        if choice.startswith("g"):
            length_text = safe_input(f"Enter desired length [{DEFAULT_GENERATE_LENGTH}]: ").strip()
            if length_text:
                try:
                    password = generate_strong_password(int(length_text))
                except ValueError as exc:
                    print(f"Error: {exc}")
                    continue
            else:
                password = generate_strong_password()
            print("Generated password:", password)
            continue
        print("Enter e, g, or q.")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate password strength or generate a strong password."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-e", "--evaluate", metavar="PASSWORD", help="Evaluate the provided password."
    )
    group.add_argument(
        "-g", "--generate", action="store_true", help="Generate a strong password."
    )
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=DEFAULT_GENERATE_LENGTH,
        help="Length for generated password (default: 16).",
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if args.generate:
        try:
            print(generate_strong_password(args.length))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.evaluate:
        result = evaluate_password(args.evaluate)
        print(format_evaluation(result))
        if result["strength"] != "Strong":
            print("\nSuggested alternative:", generate_strong_password(args.length))
        return 0
    if args.interactive:
        return interactive_mode()
    if sys.stdin.isatty():
        return interactive_mode()
    print("No action requested. Use --help for options.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
