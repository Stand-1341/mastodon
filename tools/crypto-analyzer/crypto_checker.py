import re
import sys
from pathlib import Path

PATTERNS = {
    "SHA-1 reference": r"\bsha[-_]?1\b",
    "RSA reference": r"\brsa\b",
    "ML-KEM reference": r"\bml[-_]?kem\b",
    "ML-DSA reference": r"\bml[-_]?dsa\b",
}

def scan_file(filename):
    path = Path(filename)

    if not path.is_file():
        print(f"File not found: {path}")
        return

    source = path.read_text(encoding="utf-8", errors="ignore")
    findings = 0

    print(f"\nScanning: {path}")

    for label, pattern in PATTERNS.items():
        matches = list(re.finditer(pattern, source, re.IGNORECASE))

        if matches:
            findings += len(matches)
            print(f"[REVIEW] {label}: {len(matches)} match(es)")

    if findings == 0:
        print("No configured cryptography patterns found.")

    print(f"Total pattern matches: {findings}")
    print("Note: A match is not proof of a security vulnerability.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python crypto_checker.py <source_file>")
    else:
        scan_file(sys.argv[1])
