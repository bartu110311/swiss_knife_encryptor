import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def _derive_key(password: str, salt: bytes) -> bytes:
    # 3DES requires a 192-bit (24 bytes) key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=24,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(8)  # 3DES uses 64-bit (8 bytes) block size
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(salt + iv + ciphertext).decode()

def decrypt_text(ciphertext_b64: str, password: str) -> str:
    raw_data = base64.b64decode(ciphertext_b64)
    salt, iv, ciphertext = raw_data[:16], raw_data[16:24], raw_data[24:]
    key = _derive_key(password, salt)
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(64).unpadder()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

def encrypt_file(filepath: str, out_path: str, password: str):
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(8)
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()

    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(8192):
            f_out.write(encryptor.update(padder.update(chunk)))
        f_out.write(encryptor.update(padder.finalize()) + encryptor.finalize())
    
    print(f"[+] File encrypted successfully with Triple DES (3DES): {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        salt = f_in.read(16)
        iv = f_in.read(8)
        key = _derive_key(password, salt)
        
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(64).unpadder()
        
        while chunk := f_in.read(8192):
            decrypted_chunk = decryptor.update(chunk)
            if decrypted_chunk:
                f_out.write(unpadder.update(decrypted_chunk))
                
        f_out.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())
    
    print(f"[+] File decrypted successfully with Triple DES (3DES): {out_path}")