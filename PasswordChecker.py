# Ryomen Kingsfall

import re
import argparse
import hashlib
import urllib.request
import urllib.error
import json
from typing import Dict, List

# Password strength criteria, min length and bad passwords list, can check breached passwords via HIBP
MIN_LENGTH = 14

BAD_PASSWORDS = {
    "password", "123456", "123456789", "12345",
    "password1", "qwerty", "abc123", "letmein",
    "welcome", "admin", "login", "iloveyou",
    "trustno1", "dragon", "sunshine", "master", "hello",
    "freedom", "whatever", "qazwsx", "123123", "654321",
    "superman", "1q2w3e4r", "batman", "football", "monkey",
    "shadow", "baseball", "starwars", "1234", "passw0rd"
}

SPECIAL_CHARS = r'[!@#$%^&*(),.?":{}|<>]'


# Functions to check password strength
def password_issues(password: str) -> List[str]:
    """Return a list of issues found with the password."""
    issues: List[str] = []

    if len(password) < MIN_LENGTH:
        issues.append("Password is too short.")
    if password.lower() in BAD_PASSWORDS:
        issues.append("Password is too common.")
    if not re.search(r'[A-Z]', password):
        issues.append("Missing an uppercase letter.")
    if not re.search(r'[a-z]', password):
        issues.append("Missing a lowercase letter.")
    if not re.search(r'\d', password):
        issues.append("Missing a digit.")
    if not re.search(SPECIAL_CHARS, password):
        issues.append("Missing a special character.")

    return issues


def is_strong_password(password: str) -> bool:
    return len(password_issues(password)) == 0


def password_feedback(password: str) -> str:
    issues = password_issues(password)
    if not issues:
        return "This password is strong."
    return issues[0]


# HIBP (Have I Been Pwned) pwned-passwords check via k-anonymity API
def pwned_count(password: str, timeout: int = 10) -> int:
    """Return number of times the password appears in HIBP dataset. 0 means not found.

    This uses the k-anonymity API: https://haveibeenpwned.com/API/v3#PwnedPasswords
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        raise

    for line in body.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def check_passwords_in_file(path: str, check_pwned: bool = False) -> Dict[str, Dict]:
    """Load passwords from `path` (one per line) and check each.

    Returns a dict mapping password -> {"issues": [...], "pwned": count_or_-1_on_error}
    """
    results: Dict[str, Dict] = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            pw = raw.rstrip('\n')
            if not pw:
                continue
            issues = password_issues(pw)
            pwned = None
            if check_pwned:
                try:
                    pwned = pwned_count(pw)
                except Exception:
                    pwned = -1
            results[pw] = {"issues": issues, "pwned": pwned}
    return results


def summarize_results(results: Dict[str, Dict]) -> Dict[str, int]:
    """Produce a small summary counts for the results."""
    summary = {"total": 0, "weak": 0, "pwned": 0, "pwned_errors": 0}
    for pw, info in results.items():
        summary['total'] += 1
        if info.get('issues'):
            summary['weak'] += 1
        p = info.get('pwned')
        if isinstance(p, int):
            if p > 0:
                summary['pwned'] += 1
        elif p == -1:
            summary['pwned_errors'] += 1
    return summary


def print_summary(results: Dict[str, Dict]):
    s = summarize_results(results)
    print(f"Checked {s['total']} passwords")
    print(f"Weak passwords: {s['weak']}")
    print(f"Pwned passwords: {s['pwned']}")
    if s['pwned_errors']:
        print(f"Pwned checks failed for: {s['pwned_errors']} entries")


def main():
    parser = argparse.ArgumentParser(description='Password strength and list checker')
    parser.add_argument('--file', '-f', help='Path to file with one password per line')
    parser.add_argument('--pwned', action='store_true', help='Check passwords against HIBP pwned-passwords')
    parser.add_argument('--json', help='Write results JSON to given path')
    args = parser.parse_args()

    if args.file:
        results = check_passwords_in_file(args.file, check_pwned=args.pwned)
        print_summary(results)
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as out:
                json.dump(results, out, ensure_ascii=False, indent=2)
        return

    # interactive fallback
    try:
        pw = input("Enter a password: ")
    except KeyboardInterrupt:
        print()
        return
    print(password_feedback(pw))
    try:
        strong = is_strong_password(pw)
    except Exception:
        strong = False
    print("Strong?", strong)


if __name__ == "__main__":
    main()


