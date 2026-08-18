import hashlib
import os

def hash_text(text: str) -> str:
    """Returns the SHA-256 hex digest of a given text."""
    sha256_hash = hashlib.sha256()
    # Metinleri şifrelemeden/hashlemeden önce byte'a çevirmeliyiz (utf-8)
    sha256_hash.update(text.encode('utf-8'))
    return sha256_hash.hexdigest()

def hash_file(filepath: str) -> str:
    """Returns the SHA-256 hex digest of a file, reading it in 64KB chunks."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Error: File not found -> {filepath}")
    
    sha256_hash = hashlib.sha256()
    
    # Dosyayı "rb" (read binary) modunda açıyoruz.
    # RAM'i doldurmamak için dosyayı 64KB (65536 byte) parçalar halinde okuyoruz.
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
            
    return sha256_hash.hexdigest()