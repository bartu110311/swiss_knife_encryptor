import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algos
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password: str, salt: bytes) -> bytes:
    # CAST5 maksimum 128-bit (16 bytes) anahtar destekler
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=16, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(8)  # CAST5 block size = 64 bits = 8 bytes
    key = _derive_key(password, salt)
    
    # Uyarı vermemesi için decrepit_algos.CAST5 kullanıyoruz
    cipher = Cipher(decrepit_algos.CAST5(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt_text(ciphertext_b64: str, password: str) -> str:
    raw_data = base64.b64decode(ciphertext_b64)
    salt, iv, ciphertext = raw_data[:16], raw_data[16:24], raw_data[24:]
    key = _derive_key(password, salt)
    
    cipher = Cipher(decrepit_algos.CAST5(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode()

def encrypt_file(filepath: str, out_path: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(8)
    key = _derive_key(password, salt)
    
    cipher = Cipher(decrepit_algos.CAST5(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    
    with open(filepath, 'rb') as f:
        file_data = f.read()
        
    padded_data = padder.update(file_data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(out_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print(f"[+] File encrypted successfully with CAST5: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, 'rb') as f:
        raw_data = f.read()
        
    salt, iv, ciphertext = raw_data[:16], raw_data[16:24], raw_data[24:]
    key = _derive_key(password, salt)
    
    cipher = Cipher(decrepit_algos.CAST5(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    print(f"[+] File decrypted successfully with CAST5: {out_path}")