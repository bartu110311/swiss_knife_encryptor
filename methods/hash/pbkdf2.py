import hashlib
import os
import sys

def hash_text(password: str, salt_hex: str = None, iterations: int = 100000) -> str:
    """Derives a PBKDF2-HMAC-SHA256 hash string from a password."""
    try:
        if salt_hex:
            salt = bytes.fromhex(salt_hex)
        else:
            salt = os.urandom(16)
            
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        return f"{salt.hex()}:{derived_key.hex()}"
    except Exception as e:
        sys.exit(f"[-] Error executing PBKDF2 key derivation: {e}")