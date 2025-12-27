# Ryomen Kingsfall

import re
import argparse
import hashlib
import urllib.request
import urllib.error
import json
import time
import concurrent.futures
from typing import Dict, List, Set, Optional

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
DEFAULT_WORKERS = 4
BACKOFF_BASE = 1.0
BACKOFF_FACTOR = 2.0
MAX_RETRIES = 4


def _fetch_prefix_from_hibp(prefix: str, timeout: int = 10) -> str:
    """Fetch raw HIBP range response for a 5-char prefix, with retries/backoff.

    Returns the response body as text. Raises on unrecoverable errors.
    """
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "PasswordChecker/1.0"})
    backoff = BACKOFF_BASE
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            code = getattr(e, 'code', None)
            if code == 429 or (500 <= (code or 0) < 600):
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(backoff)
                backoff *= BACKOFF_FACTOR
                continue
            raise
        except urllib.error.URLError:
            if attempt == MAX_RETRIES:
                raise
            time.sleep(backoff)
            backoff *= BACKOFF_FACTOR
    raise RuntimeError("Failed to fetch prefix after retries")


def _parse_range_body(body: str) -> Dict[str, int]:
    """Parse HIBP range body into mapping of suffix -> count."""
    d: Dict[str, int] = {}
    for line in body.splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 2:
            continue
        h, count = parts
        try:
            d[h] = int(count)
        except ValueError:
            continue
    return d


def _mask_password(pw: str) -> str:
    """Return a masked representation of a password (not reversible)."""
    if not pw:
        return ""
    if len(pw) <= 2:
        return "**"
    return pw[0] + "*" * min(6, len(pw) - 2) + pw[-1]


def pwned_count(password: str, timeout: int = 10) -> int:
    """Compatibility wrapper: single-password check (not optimized for large lists)."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    body = _fetch_prefix_from_hibp(prefix, timeout=timeout)
    table = _parse_range_body(body)
    return table.get(suffix, 0)


def check_passwords_in_file(path: str, check_pwned: bool = False, workers: int = DEFAULT_WORKERS, progress_interval: int = 1000) -> Dict[str, Dict]:
    """Load passwords from `path` (one per line) and check each.

    Returns a dict mapping `sha1:<HEX>` -> {"masked": str, "issues": [...], "pwned": count_or_-1_on_error}
    Raw passwords are never stored in the returned dict or written to disk.
    """
    entries: List[Dict] = []
    prefixes: Set[str] = set()
    total = 0

    # First pass: read file, compute sha1/prefix/suffix and local strength issues
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            pw = raw.rstrip('\n')
            if not pw:
                continue
            total += 1
            sha1 = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            prefixes.add(prefix)
            entries.append({
                'sha1': sha1,
                'prefix': prefix,
                'suffix': suffix,
                'masked': _mask_password(pw),
                'issues': password_issues(pw),
                'pwned': None,
            })
            if total % progress_interval == 0:
                print(f"Read {total} passwords...")

    if check_pwned and prefixes:
        # Fetch prefixes in parallel with caching
        prefix_cache: Dict[str, Optional[Dict[str, int]]] = {}

        def _fetch_and_parse(pref: str) -> (str, Optional[Dict[str, int]]):
            try:
                body = _fetch_prefix_from_hibp(pref)
                return pref, _parse_range_body(body)
            except Exception:
                return pref, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_fetch_and_parse, p): p for p in prefixes}
            fetched = 0
            for fut in concurrent.futures.as_completed(futures):
                pref = futures[fut]
                try:
                    p, table = fut.result()
                    prefix_cache[p] = table
                except Exception:
                    prefix_cache[pref] = None
                fetched += 1
                if fetched % max(1, workers) == 0:
                    print(f"Fetched {fetched}/{len(prefixes)} prefixes...")

        # Populate pwned counts per entry
        for i, e in enumerate(entries, 1):
            table = prefix_cache.get(e['prefix'])
            if table is None:
                e['pwned'] = -1
            else:
                e['pwned'] = table.get(e['suffix'], 0)
            if i % progress_interval == 0:
                print(f"Processed {i}/{len(entries)} passwords...")

    # Build results keyed by sha1 to avoid storing plaintext
    results: Dict[str, Dict] = {}
    for e in entries:
        key = f"sha1:{e['sha1']}"
        results[key] = {"masked": e['masked'], "issues": e['issues'], "pwned": e['pwned']}

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
    parser.add_argument('--workers', type=int, default=DEFAULT_WORKERS, help='Number of concurrent workers for prefix fetching')
    parser.add_argument('--progress', type=int, default=1000, help='Print progress every N passwords read/processed')
    parser.add_argument('--json', help='Write results JSON to given path (will not contain raw passwords)')
    args = parser.parse_args()

    if args.file:
        results = check_passwords_in_file(args.file, check_pwned=args.pwned, workers=args.workers, progress_interval=args.progress)
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


