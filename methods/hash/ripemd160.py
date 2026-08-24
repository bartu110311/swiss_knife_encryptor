import hashlib
from cryptography.hazmat.primitives import hashes

def hash_text(text: str) -> str:
    try:
        return hashlib.new("ripemd160", text.encode("utf-8")).hexdigest()
    except ValueError:
        digest = hashes.Hash(hashes.RIPEMD160())
        digest.update(text.encode("utf-8"))
        return digest.finalize().hex()

def hash_file(file_path: str) -> str:
    try:
        h = hashlib.new("ripemd160")
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except ValueError:
        digest = hashes.Hash(hashes.RIPEMD160())
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                digest.update(chunk)
        return digest.finalize().hex()