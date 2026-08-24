import base64
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def _derive_key(password: str, salt: bytes, key_bytes: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_bytes,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_text(text: str, password: str, bits: int = 256) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = _derive_key(password, salt, bits // 8)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode("utf-8")) + padder.finalize()
    
    cipher = Cipher(algorithms.ARIA(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(salt + iv + ct).decode("utf-8")

def decrypt_text(cipher_text: str, password: str, bits: int = 256) -> str:
    raw = base64.b64decode(cipher_text.encode("utf-8"))
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = _derive_key(password, salt, bits // 8)
    
    cipher = Cipher(algorithms.ARIA(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode("utf-8")

def encrypt_file(input_path: str, output_path: str, password: str, bits: int = 256):
    with open(input_path, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = _derive_key(password, salt, bits // 8)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.ARIA(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_path, "wb") as f:
        f.write(salt + iv + ct)

def decrypt_file(input_path: str, output_path: str, password: str, bits: int = 256):
    with open(input_path, "rb") as f:
        raw = f.read()
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = _derive_key(password, salt, bits // 8)
    
    cipher = Cipher(algorithms.ARIA(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    with open(output_path, "wb") as f:
        f.write(data)