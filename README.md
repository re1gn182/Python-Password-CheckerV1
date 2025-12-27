# PasswordChecker by RyomenKingsfall

A small password strength and list checker.

Usage:

- Interactive: `python3 PasswordChecker.py`
- Check a file: `python3 PasswordChecker.py --file passwords.txt`
- Check file with HIBP (Have I Been Pwned) pwned-passwords lookup:

```bash
python3 PasswordChecker.py --file passwords.txt --pwned --workers 4 --progress 1000 --json results.json
```

Security notes:
- The tool does NOT write raw plaintext passwords to disk when `--json` is used. Instead results are keyed by the SHA1 hash and include a masked representation.
- HIBP requests use the k-anonymity API: only the first 5 hex chars of the SHA1 are sent to the remote service.
- Be mindful of rate limits; this tool includes retries and backoff but avoid hammering the HIBP service.

Tests:
Run unit tests with:

```bash
python3 -m unittest discover -v
```
