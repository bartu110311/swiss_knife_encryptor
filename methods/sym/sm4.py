import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password: str, salt: bytes) -> bytes:
    # SM4 strictly uses 128-bit (16 bytes) keys
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt_text(ciphertext_b64: str, password: str) -> str:
    data = base64.b64decode(ciphertext_b64)
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    
    key = _derive_key(password, salt)
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode('utf-8')

def encrypt_file(filepath: str, out_path: str, password: str):
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(8192):
            padded_chunk = padder.update(chunk)
            f_out.write(encryptor.update(padded_chunk))
        f_out.write(encryptor.update(padder.finalize()) + encryptor.finalize())
    print(f"[+] Successfully encrypted with SM4: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        salt = f_in.read(16)
        iv = f_in.read(16)
        key = _derive_key(password, salt)
        
        cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        while chunk := f_in.read(8192):
            decrypted_chunk = decryptor.update(chunk)
            if decrypted_chunk:
                unpadded = unpadder.update(decrypted_chunk)
                f_out.write(unpadded)
                
        f_out.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())
    print(f"[+] Successfully decrypted with SM4: {out_path}")