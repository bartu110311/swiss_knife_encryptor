import hashlib
import sys

def hash_text(text: str, variant: str = "256") -> str:
    """Hashes a plain text using SHA-3."""
    text_bytes = text.encode('utf-8')
    if variant == "256":
        return hashlib.sha3_256(text_bytes).hexdigest()
    elif variant == "512":
        return hashlib.sha3_512(text_bytes).hexdigest()
    else:
        sys.exit("[-] Error: Unsupported SHA-3 variant.")

def hash_file(filepath: str, variant: str = "256") -> str:
    """Hashes a file using SHA-3."""
    try:
        if variant == "256":
            h = hashlib.sha3_256()
        elif variant == "512":
            h = hashlib.sha3_512()
        else:
            sys.exit("[-] Error: Unsupported SHA-3 variant.")
            
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        sys.exit(f"[-] Error hashing file: {e}")