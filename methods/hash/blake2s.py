import hashlib

def hash_text(text: str) -> str:
    return hashlib.blake2s(text.encode()).hexdigest()

def hash_file(filepath: str) -> str:
    h = hashlib.blake2s()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()