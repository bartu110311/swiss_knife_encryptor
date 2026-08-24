from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import sys

def generate_keypair(priv_path: str, pub_path: str):
    """Generates an ECDH (SECP256R1) keypair for key exchange."""
    try:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_key = priv_key.public_key()
        
        with open(priv_path, "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[+] ECDH Keypair generated: {priv_path}, {pub_path}")
    except Exception as e:
        sys.exit(f"[-] Error generating ECDH keys: {e}")

def derive_shared_secret(priv_path: str, peer_pub_path: str) -> str:
    """Derives a 256-bit shared key using local private key and peer's public key."""
    try:
        with open(priv_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(peer_pub_path, "rb") as f:
            peer_pub_key = serialization.load_pem_public_key(f.read())
            
        shared_key = priv_key.exchange(ec.ECDH(), peer_pub_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecdh shared secret',
        ).derive(shared_key)
        
        return derived_key.hex()
    except Exception as e:
        sys.exit(f"[-] Error deriving ECDH shared secret: {e}")