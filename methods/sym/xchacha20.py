import hashlib
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305

def encrypt_text(text: str, password: str) -> str:
    """Encrypts text using XChaCha20-Poly1305 AEAD cipher."""
    try:
        key = hashlib.sha256(password.encode()).digest()
        xchacha = XChaCha20Poly1305(key)
        nonce = os.urandom(24)
        ciphertext = xchacha.encrypt(nonce, text.encode('utf-8'), None)
        return (nonce + ciphertext).hex()
    except Exception as e:
        sys.exit(f"[-] Error encrypting with XChaCha20: {e}")

def decrypt_text(cipher_hex: str, password: str) -> str:
    """Decrypts XChaCha20-Poly1305 ciphertext hex string."""
    try:
        raw = bytes.fromhex(cipher_hex)
        nonce = raw[:24]
        ciphertext = raw[24:]
        key = hashlib.sha256(password.encode()).digest()
        xchacha = XChaCha20Poly1305(key)
        decrypted = xchacha.decrypt(nonce, ciphertext, None)
        return decrypted.decode('utf-8')
    except Exception as e:
        sys.exit(f"[-] Error decrypting with XChaCha20: {e}")

def encrypt_file(in_path: str, out_path: str, password: str):
    """Encrypts a file using XChaCha20-Poly1305 AEAD cipher."""
    try:
        with open(in_path, 'rb') as f:
            data = f.read()
        key = hashlib.sha256(password.encode()).digest()
        xchacha = XChaCha20Poly1305(key)
        nonce = os.urandom(24)
        ciphertext = xchacha.encrypt(nonce, data, None)
        with open(out_path, 'wb') as f:
            f.write(nonce + ciphertext)
        print(f"[+] File encrypted with XChaCha20: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error encrypting file with XChaCha20: {e}")

def decrypt_file(in_path: str, out_path: str, password: str):
    """Decrypts an XChaCha20-Poly1305 encrypted file."""
    try:
        with open(in_path, 'rb') as f:
            raw = f.read()
        nonce = raw[:24]
        ciphertext = raw[24:]
        key = hashlib.sha256(password.encode()).digest()
        xchacha = XChaCha20Poly1305(key)
        decrypted = xchacha.decrypt(nonce, ciphertext, None)
        with open(out_path, 'wb') as f:
            f.write(decrypted)
        print(f"[+] File decrypted with XChaCha20: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error decrypting file with XChaCha20: {e}")