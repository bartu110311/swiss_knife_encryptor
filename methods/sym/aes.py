import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def _derive_key(password: str, salt: bytes, bits: int) -> bytes:
    key_length = bits // 8  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_text(text: str, password: str, bits: int = 256) -> str:
    salt = os.urandom(16) 
    key = _derive_key(password, salt, bits)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) 
    
    ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    
    # HARİKA FİKRİN BURADA DEVREYE GİRİYOR: 
    # Bit uzunluğunu (byte cinsinden) şifreli metnin en başına ekliyoruz (1 byte)
    key_length_byte = bytes([bits // 8]) 
    
    encrypted_data = key_length_byte + salt + nonce + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_text(encrypted_b64: str, password: str) -> str:
    """Bits parametresini kaldırdık, artık verinin içinden otomatik okuyor."""
    try:
        raw_data = base64.b64decode(encrypted_b64)
        
        # İlk 1 byte'ı okuyup anahtar uzunluğunu tespit ediyoruz
        key_length = raw_data[0] 
        bits = key_length * 8
        
        salt = raw_data[1:17]
        nonce = raw_data[17:29]
        ciphertext = raw_data[29:]
        
        key = _derive_key(password, salt, bits)
        aesgcm = AESGCM(key)
        
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception as e:
        raise ValueError("Decryption failed! Wrong password or corrupted data.")

def encrypt_file(filepath: str, out_path: str, password: str, bits: int = 256):
    """Dosyayı okur, AES-GCM ile şifreler ve yeni dosyaya yazar."""
    with open(filepath, "rb") as f:
        data = f.read()
    
    salt = os.urandom(16)
    key = _derive_key(password, salt, bits)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    ciphertext = aesgcm.encrypt(nonce, data, None)
    key_length_byte = bytes([bits // 8])
    
    with open(out_path, "wb") as f:
        f.write(key_length_byte + salt + nonce + ciphertext)

def decrypt_file(filepath: str, out_path: str, password: str):
    """Şifreli dosyayı okur, AES-GCM ile çözer ve orjinal halinde kaydeder."""
    with open(filepath, "rb") as f:
        raw_data = f.read()
        
    key_length = raw_data[0]
    bits = key_length * 8
    salt = raw_data[1:17]
    nonce = raw_data[17:29]
    ciphertext = raw_data[29:]
    
    key = _derive_key(password, salt, bits)
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    
    with open(out_path, "wb") as f:
        f.write(decrypted_data)