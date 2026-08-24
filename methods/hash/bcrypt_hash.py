import bcrypt
import sys

def hash_text(password: str) -> str:
    """Hashes a plain text password using Bcrypt with automatic salt."""
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        sys.exit(f"[-] Error executing Bcrypt hashing: {e}")

def verify_text(password: str, hashed_str: str) -> bool:
    """Verifies a plain text password against a Bcrypt hash string."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_str.encode('utf-8'))
    except Exception as e:
        sys.exit(f"[-] Error verifying Bcrypt hash: {e}")