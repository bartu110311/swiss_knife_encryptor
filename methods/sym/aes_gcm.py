import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=key_size, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text: str, password: str, bits: int = 256) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt, bits // 8)
    nonce = os.urandom(12)  # AES-GCM için standart nonce boyutu 12 byte'tır
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
    
    return base64.b64encode(salt + nonce + ciphertext).decode()

def decrypt_text(ciphertext_b64: str, password: str, bits: int = 256) -> str:
    raw_data = base64.b64decode(ciphertext_b64)
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:28], raw_data[28:]
    key = _derive_key(password, salt, bits // 8)
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def encrypt_file(filepath: str, out_path: str, password: str, bits: int = 256):
    salt = os.urandom(16)
    key = _derive_key(password, salt, bits // 8)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    
    with open(filepath, 'rb') as f:
        file_data = f.read()
        
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    
    with open(out_path, 'wb') as f:
        f.write(salt + nonce + ciphertext)
    print(f"[+] File encrypted successfully with AES-GCM: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str, bits: int = 256):
    with open(filepath, 'rb') as f:
        raw_data = f.read()
        
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:28], raw_data[28:]
    key = _derive_key(password, salt, bits // 8)
    aesgcm = AESGCM(key)
    
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    print(f"[+] File decrypted successfully with AES-GCM: {out_path}")