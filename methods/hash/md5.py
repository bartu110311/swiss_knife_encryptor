import hashlib
import sys

def hash_text(text: str) -> str:
    """Hashes text using MD5 (Legacy hash for checksums)."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def hash_file(filepath: str) -> str:
    """Hashes a file using MD5."""
    try:
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        sys.exit(f"[-] Error hashing file with MD5: {e}")