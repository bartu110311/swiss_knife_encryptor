import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
    nonce = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(salt + nonce + ciphertext).decode()

def decrypt_text(ciphertext_b64: str, password: str, bits: int = 256) -> str:
    raw_data = base64.b64decode(ciphertext_b64)
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    key = _derive_key(password, salt, bits // 8)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def encrypt_file(filepath: str, out_path: str, password: str, bits: int = 256):
    salt = os.urandom(16)
    key = _derive_key(password, salt, bits // 8)
    nonce = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(filepath, 'rb') as f:
        ciphertext = encryptor.update(f.read()) + encryptor.finalize()
        
    with open(out_path, 'wb') as f:
        f.write(salt + nonce + ciphertext)
    print(f"[+] File encrypted successfully with AES-CTR: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str, bits: int = 256):
    with open(filepath, 'rb') as f:
        raw_data = f.read()
        
    salt, nonce, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    key = _derive_key(password, salt, bits // 8)
    
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    print(f"[+] File decrypted successfully with AES-CTR: {out_path}")