import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def _derive_key(password: str, salt: bytes, bits: int) -> bytes:
    """Kullanıcının girdiği parolayı, istenilen bit uzunluğunda güvenli bir AES anahtarına çevirir."""
    key_length = bits // 8  # 256 bit -> 32 byte, 128 bit -> 16 byte
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000, # Şifre kırmayı zorlaştırmak için bilerek yavaşlatıyoruz
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_text(text: str, password: str, bits: int = 256) -> str:
    """Metni AES-GCM ile şifreler."""
    salt = os.urandom(16) # Her şifrelemede rastgele bir tuz (salt) üretilir
    key = _derive_key(password, salt, bits)
    aesgcm = AESGCM(key)
    
    nonce = os.urandom(12) # GCM modu için 12 bytelık rastgele bir sayı (IV)
    
    data_to_encrypt = text.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, None)
    
    # Şifreyi çözerken salt ve nonce değerlerine ihtiyacımız olacak, 
    # bu yüzden onları şifreli metnin başına ekleyip Base64'e çeviriyoruz.
    encrypted_data = salt + nonce + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_text(encrypted_b64: str, password: str, bits: int = 256) -> str:
    """AES-GCM ile şifrelenmiş metni çözer."""
    try:
        raw_data = base64.b64decode(encrypted_b64)
        
        # Veriyi parçalıyoruz: ilk 16 byte salt, sonraki 12 byte nonce, kalanı şifreli metin
        salt = raw_data[:16]
        nonce = raw_data[16:28]
        ciphertext = raw_data[28:]
        
        key = _derive_key(password, salt, bits)
        aesgcm = AESGCM(key)
        
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError("Decryption failed! Wrong password, corrupted data, or wrong bit size.")