import hashlib
import os

def hash_text(text: str) -> str:
    sha512_hash = hashlib.sha512()
    sha512_hash.update(text.encode('utf-8'))
    return sha512_hash.hexdigest()

def hash_file(filepath: str) -> str:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Error: File not found -> {filepath}")
    
    sha512_hash = hashlib.sha512()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()