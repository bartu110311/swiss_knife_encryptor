import sys
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def _derive_key(password: str) -> bytes:
    """Derives a 16-byte key for RC4 using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).digest()[:16]

def encrypt_text(text: str, password: str) -> str:
    """Encrypts text using RC4 stream cipher and returns hex string."""
    try:
        key = _derive_key(password)
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
        return ciphertext.hex()
    except Exception as e:
        sys.exit(f"[-] Error encrypting text with RC4: {e}")

def decrypt_text(hex_str: str, password: str) -> str:
    """Decrypts hex string using RC4 stream cipher."""
    try:
        key = _derive_key(password)
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        decryptor = cipher.decryptor()
        ciphertext = bytes.fromhex(hex_str)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        sys.exit(f"[-] Error decrypting text with RC4: {e}")

def encrypt_file(in_path: str, out_path: str, password: str):
    """Encrypts a file using RC4 stream cipher."""
    try:
        key = _derive_key(password)
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        encryptor = cipher.encryptor()
        
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            while chunk := fin.read(4096):
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
        print(f"[+] File encrypted successfully with RC4: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error encrypting file with RC4: {e}")

def decrypt_file(in_path: str, out_path: str, password: str):
    """Decrypts a file using RC4 stream cipher."""
    try:
        key = _derive_key(password)
        cipher = Cipher(algorithms.ARC4(key), mode=None)
        decryptor = cipher.decryptor()
        
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            while chunk := fin.read(4096):
                fout.write(decryptor.update(chunk))
            fout.write(decryptor.finalize())
        print(f"[+] File decrypted successfully with RC4: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error decrypting file with RC4: {e}")