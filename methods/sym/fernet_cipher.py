import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    # Fernet, urlsafe base64 formatında tam 32 byte anahtar bekler
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    ciphertext = f.encrypt(text.encode())
    
    combined = salt + ciphertext
    return base64.b64encode(combined).decode()

def decrypt_text(ciphertext_b64: str, password: str) -> str:
    raw_data = base64.b64decode(ciphertext_b64)
    salt, ciphertext = raw_data[:16], raw_data[16:]
    key = _derive_key(password, salt)
    f = Fernet(key)
    
    return f.decrypt(ciphertext).decode()

def encrypt_file(filepath: str, out_path: str, password: str):
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    
    with open(filepath, 'rb') as file:
        file_data = file.read()
        
    encrypted_data = f.encrypt(file_data)
    
    with open(out_path, 'wb') as file:
        file.write(salt + encrypted_data)
    print(f"[+] File encrypted successfully with Fernet: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, 'rb') as file:
        raw_data = file.read()
        
    salt, encrypted_data = raw_data[:16], raw_data[16:]
    key = _derive_key(password, salt)
    f = Fernet(key)
    
    decrypted_data = f.decrypt(encrypted_data)
    
    with open(out_path, 'wb') as file:
        file.write(decrypted_data)
    print(f"[+] File decrypted successfully with Fernet: {out_path}")