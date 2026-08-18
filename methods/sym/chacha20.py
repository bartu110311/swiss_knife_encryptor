import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def _derive_key(password: str, salt: bytes) -> bytes:
    # ChaCha20 her zaman 256-bit (32 byte) anahtar kullanır
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password.encode('utf-8'))

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, text.encode('utf-8'), None)
    return base64.b64encode(salt + nonce + ciphertext).decode('utf-8')

def decrypt_text(encrypted_b64: str, password: str) -> str:
    raw_data = base64.b64decode(encrypted_b64)
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:28], raw_data[28:]
    key = _derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None).decode('utf-8')

def encrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, "rb") as f: data = f.read()
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    with open(out_path, "wb") as f:
        f.write(salt + nonce + chacha.encrypt(nonce, data, None))

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, "rb") as f: raw_data = f.read()
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:28], raw_data[28:]
    key = _derive_key(password, salt)
    chacha = ChaCha20Poly1305(key)
    with open(out_path, "wb") as f:
        f.write(chacha.decrypt(nonce, ciphertext, None))