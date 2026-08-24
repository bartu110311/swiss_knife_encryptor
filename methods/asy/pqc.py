import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PQCManager:
    """
    PyCrypto bağımlılığı kaldırılmış, modern 'cryptography' kütüphanesi kullanan
    Post-Quantum Cryptography (PQC) yönetim sınıfı.
    """
    def __init__(self, key_size: int = 32):
        # Kuantum sonrası güvenlik için en az 256-bit (32 byte) anahtar boyutu
        self.key_size = key_size

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Kuantum dayanıklı anahtar çifti (Private / Public Key) türetimi.
        (SHA3-512 tabanlı hibrit türetim simülasyonu)
        """
        private_key = os.urandom(self.key_size)
        # Kuantum dirençli SHA3-512 ile public key türetimi
        public_key = hashlib.sha3_512(private_key).digest()[:32]
        return private_key, public_key

    def encapsulate_secret(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Kuantum Dayanıklı Anahtar Kapsülleme (KEM) simülasyonu.
        Geriye (shared_secret, ciphertext/capsule) döner.
        """
        ephemeral_secret = os.urandom(32)
        shared_secret = hashlib.sha3_256(ephemeral_secret + public_key).digest()
        ciphertext_capsule = hashlib.sha3_256(ephemeral_secret).digest()
        return shared_secret, ciphertext_capsule

    def encrypt_data(self, plaintext: str, secret_key: bytes) -> dict:
        """
        AES-256-GCM ile authenticated veri şifreleme.
        Grover algoritmasına karşı 256-bit AES kuantum güvenlidir.
        """
        if len(secret_key) != 32:
            secret_key = hashlib.sha3_256(secret_key).digest()

        aesgcm = AESGCM(secret_key)
        nonce = os.urandom(12)  # 96-bit standart GCM nonce
        data_bytes = plaintext.encode('utf-8')
        
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

        return {
            "nonce": nonce,
            "ciphertext": ciphertext
        }

    def decrypt_data(self, encrypted_package: dict, secret_key: bytes) -> str:
        """
        AES-256-GCM ile şifrelenmiş veriyi çözme.
        """
        if len(secret_key) != 32:
            secret_key = hashlib.sha3_256(secret_key).digest()

        aesgcm = AESGCM(secret_key)
        decrypted_bytes = aesgcm.decrypt(
            encrypted_package["nonce"], 
            encrypted_package["ciphertext"], 
            None
        )
        return decrypted_bytes.decode('utf-8')