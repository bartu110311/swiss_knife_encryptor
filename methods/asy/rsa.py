from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def generate_keypair(priv_path: str, pub_path: str, key_size: int = 2048):
    """Genel (Public) ve Gizli (Private) anahtar çifti oluşturup dosyalara kaydeder."""
    # 1. Anahtarları üret
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    # 2. Private Key'i PEM formatında dosyaya yaz
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # İleride private key'e de şifre koyabiliriz
        ))

    # 3. Public Key'i PEM formatında dosyaya yaz
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def encrypt_text(text: str, pubkey_path: str) -> str:
    """Public Key dosyasını okuyarak metni şifreler."""
    with open(pubkey_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    ciphertext = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_text(encrypted_b64: str, privkey_path: str) -> str:
    """Private Key dosyasını okuyarak şifrelenmiş metni çözer."""
    with open(privkey_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    raw_data = base64.b64decode(encrypted_b64)
    plaintext = private_key.decrypt(
        raw_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')