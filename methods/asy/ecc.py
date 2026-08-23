from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def generate_keypair(priv_path: str, pub_path: str):
    # SECP256R1 (P-256) standardında bir eliptik eğri anahtarı üretiyoruz.
    # Bu, Bitcoin ve modern web'de kullanılan standartlardan biridir.
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Private Key'i PEM formatında kaydet
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)

    # Public Key'i PEM formatında kaydet
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)
    
    print(f"ECC Key pair created succesfully!\nPrivate Key: {priv_path}\nPublic Key: {pub_path}")

def sign_file(filepath: str, sig_path: str, privkey_path: str):
    with open(privkey_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    
    hasher = hashes.Hash(hashes.SHA256())
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    digest = hasher.finalize()

    from cryptography.hazmat.primitives.asymmetric import utils
    signature = priv_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    with open(sig_path, "wb") as f:
        f.write(signature)
    print(f"[+] ECC Digital Signature created successfully at: {sig_path}")

def verify_file(filepath: str, sig_path: str, pubkey_path: str) -> bool:
    with open(pubkey_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
        
    with open(sig_path, "rb") as f:
        signature = f.read()
        
    hasher = hashes.Hash(hashes.SHA256())
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    digest = hasher.finalize()

    from cryptography.hazmat.primitives.asymmetric import utils
    try:
        pub_key.verify(
            signature,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        print(f"[+] VERIFIED: The signature is VALID. The file '{filepath}' is authentic and unmodified.")
        return True
    except Exception:
        print(f"[-] WARNING: INVALID signature! The file '{filepath}' may have been tampered with or the wrong key was used.")
        return False