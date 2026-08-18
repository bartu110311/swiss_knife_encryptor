from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def _derive_key(password: str, salt: bytes, bits: int) -> bytes:
    # ÖNEMLİ: XTS modu her zaman seçilen bitin 2 katı uzunluğunda anahtar ister.
    # 256 bit AES-XTS için 512 bit (64 byte) anahtar üretmeliyiz.
    key_len = (bits * 2) // 8
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=100000)
    return kdf.derive(password.encode('utf-8'))

def _process_chunk(chunk: bytes, key: bytes, chunk_idx: int, encrypt: bool) -> bytes:
    # XTS için "tweak" değeri (Genelde sektör numarasıdır, 16 byte olmalıdır)
    tweak = chunk_idx.to_bytes(16, byteorder='little')
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    
    if encrypt:
        encryptor = cipher.encryptor()
        return encryptor.update(chunk) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        return decryptor.update(chunk) + decryptor.finalize()