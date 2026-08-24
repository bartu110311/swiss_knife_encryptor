import hashlib
import os
import sys

def hash_text(password: str, salt_hex: str = None, n: int = 16384, r: int = 8, p: int = 1) -> str:
    """Generates a Scrypt memory-hard hash string formatted as salt:derived_key."""
    try:
        if salt_hex:
            salt = bytes.fromhex(salt_hex)
        else:
            salt = os.urandom(16)
            
        derived_key = hashlib.scrypt(
            password.encode('utf-8'),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=64 * 1024 * 1024
        )
        return f"{salt.hex()}:{derived_key.hex()}"
    except Exception as e:
        sys.exit(f"[-] Error executing Scrypt key derivation: {e}")