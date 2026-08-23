import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def _derive_key(password: str, salt: bytes) -> bytes:
    # SEED strictly uses a 128-bit (16 bytes) key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, out_path: str, password: str):
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    iv = os.urandom(16)  # SEED uses 128-bit (16 bytes) block size
    
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(8192):
            f_out.write(encryptor.update(padder.update(chunk)))
        f_out.write(encryptor.update(padder.finalize()) + encryptor.finalize())
    
    print(f"[+] File successfully encrypted with SEED: {out_path}")

def decrypt_file(filepath: str, out_path: str, password: str):
    with open(filepath, 'rb') as f_in, open(out_path, 'wb') as f_out:
        salt = f_in.read(16)
        iv = f_in.read(16)
        key = _derive_key(password, salt)
        
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        
        while chunk := f_in.read(8192):
            decrypted_chunk = decryptor.update(chunk)
            if decrypted_chunk:
                f_out.write(unpadder.update(decrypted_chunk))
                
        f_out.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())
    
    print(f"[+] File successfully decrypted with SEED: {out_path}")