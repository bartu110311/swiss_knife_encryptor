from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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