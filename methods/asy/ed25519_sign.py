from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import sys

def generate_keypair(priv_path: str, pub_path: str):
    """Generates an Ed25519 keypair for high-speed digital signatures."""
    try:
        priv_key = ed25519.Ed25519PrivateKey.generate()
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
        print(f"[+] Ed25519 Keypair generated: {priv_path}, {pub_path}")
    except Exception as e:
        sys.exit(f"[-] Error generating Ed25519 keys: {e}")
        
def sign_file(filepath: str, sig_path: str, priv_path: str):
    """Signs a file using an Ed25519 private key."""
    try:
        with open(priv_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(filepath, "rb") as f:
            data = f.read()
            
        signature = priv_key.sign(data)
        
        with open(sig_path, "wb") as f:
            f.write(signature)
        print(f"[+] File signed successfully with Ed25519. Signature saved to: {sig_path}")
    except Exception as e:
        sys.exit(f"[-] Error signing file: {e}")
        
def verify_file(filepath: str, sig_path: str, pub_path: str) -> bool:
    """Verifies a file's Ed25519 signature."""
    try:
        with open(pub_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        with open(filepath, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()
            
        pub_key.verify(signature, data)
        print("[+] SUCCESS: Ed25519 Signature is VALID and authentic.")
        return True
    except Exception:
        print("[-] WARNING: Ed25519 Signature is INVALID or file is tampered!")
        return False