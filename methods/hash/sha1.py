import hashlib
import os

def hash_text(text: str) -> str:
    """Returns the SHA-1 hex digest of a given text."""
    sha1_hash = hashlib.sha1()
    sha1_hash.update(text.encode('utf-8'))
    return sha1_hash.hexdigest()

def hash_file(filepath: str) -> str:
    """Returns the SHA-1 hex digest of a file, reading it in 64KB chunks."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Error: File not found -> {filepath}")
    
    sha1_hash = hashlib.sha1()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha1_hash.update(byte_block)
            
    return sha1_hash.hexdigest()