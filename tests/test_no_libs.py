"""No forbidden crypto-library imports anywhere in crypto_core/."""
import os, re

FORBIDDEN_IMPORTS = [
    r"^from\s+Crypto\b", r"^import\s+Crypto\b",
    r"^from\s+cryptography\b", r"^import\s+cryptography\b",
    r"^import\s+hashlib\b", r"^from\s+hashlib\b",
    r"^import\s+hmac\b", r"^from\s+hmac\b",
    r"^import\s+secrets\b", r"^from\s+secrets\b",
    r"^import\s+nacl\b", r"^from\s+nacl\b",
    r"^import\s+rsa\b", r"^from\s+rsa\b",
]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRYPTO_CORE = os.path.join(ROOT, "crypto_core")


def iter_py(directory):
    for dirpath, _, filenames in os.walk(directory):
        if "__pycache__" in dirpath:
            continue
        for f in filenames:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)


def test_no_forbidden_imports():
    bad = []
    for fp in iter_py(CRYPTO_CORE):
        with open(fp) as f:
            for line in f:
                s = line.strip()
                if s.startswith("#"):
                    continue
                for pat in FORBIDDEN_IMPORTS:
                    if re.match(pat, s):
                        bad.append((fp, s))
                        break
    assert not bad, "Forbidden imports:\n" + "\n".join(f"  {fp}: {s}" for fp, s in bad)


def test_os_urandom_chokepoint():
    """Only common/randomness.py may import os.urandom."""
    allowed = os.path.normpath(os.path.join(CRYPTO_CORE, "common", "randomness.py"))
    bad = []
    for fp in iter_py(CRYPTO_CORE):
        if os.path.normpath(fp) == allowed:
            continue
        with open(fp) as f:
            content = f.read()
        if "os.urandom" in content:
            bad.append(fp)
    assert not bad, f"os.urandom called outside randomness.py: {bad}"
