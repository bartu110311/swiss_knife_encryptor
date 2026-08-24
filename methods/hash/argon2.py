import sys
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:
    sys.exit("[-] Error: 'argon2-cffi' package is missing. Please install it via 'pip install argon2-cffi'.")

def hash_text(text: str) -> str:
    """Hashes a text password using Argon2id."""
    ph = PasswordHasher()
    return ph.hash(text)

def verify_text(text: str, hash_str: str) -> bool:
    """Verifies a plain text string against an Argon2 hash."""
    ph = PasswordHasher()
    try:
        ph.verify(hash_str, text)
        return True
    except VerifyMismatchError:
        return False