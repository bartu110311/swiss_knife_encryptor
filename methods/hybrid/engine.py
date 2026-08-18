import os
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def encrypt_file(filepath: str, out_path: str, pubkey_path: str, asy_algo: str, sym_algo: str):
    # 1. Asimetrik Public Key'i Oku
    with open(pubkey_path, "rb") as f:
        pubkey_bytes = f.read()
    pubkey = serialization.load_pem_public_key(pubkey_bytes)

    # 2. Seçimleri ID'lere Dönüştür (İleride yeni algoritma eklemek çok kolay olacak)
    asy_id = 1 if asy_algo == "rsa" else 2  # 1: RSA, 2: ECC
    sym_id = 1 if sym_algo == "aes" else 2  # 1: AES, 2: ChaCha20
    
    # 3. Kırılması imkansız 256-bit (32 byte) rastgele bir şifre üret! (Ana kilit)
    sym_key = os.urandom(32)

    # 4. Asimetrik Şifreleme (Parolayı koruma altına al)
    if asy_id == 1: # RSA Kullanılıyorsa
        enc_key = pubkey.encrypt(
            sym_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    else: # ECC Kullanılıyorsa (ECDH - Anahtar Takası)
        # Geçici bir ECC anahtarı üret
        eph_priv = ec.generate_private_key(ec.SECP256R1())
        # Ortak bir sır (shared secret) türet
        shared_key = eph_priv.exchange(ec.ECDH(), pubkey)
        # Türetilen bu sırrı, 32 byte'lık gerçek simetrik anahtarımıza zorla (HKDF)
        sym_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid_ecc").derive(shared_key)
        
        # Karşı tarafın çözebilmesi için, ürettiğimiz geçici public key'i dosyaya koymamız lazım (enc_key yerine geçecek)
        enc_key = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # 5. Dosyayı Oku
    with open(filepath, "rb") as f:
        data = f.read()

    # 6. Simetrik Şifreleme (Dosyayı ışık hızında şifrele)
    nonce = os.urandom(12)
    if sym_id == 1:
        cipher = AESGCM(sym_key)
    else:
        cipher = ChaCha20Poly1305(sym_key)
    ciphertext = cipher.encrypt(nonce, data, None)

    # 7. Her şeyi tek dosyada birleştir!
    # FORMAT: [Asy ID - 1 Byte] + [Sym ID - 1 Byte] + [Key Uzunluğu - 2 Byte] + [Şifreli Key/Geçici PubKey] + [Nonce 12 Byte] + [Ciphertext]
    with open(out_path, "wb") as f:
        f.write(struct.pack(">BBH", asy_id, sym_id, len(enc_key)))
        f.write(enc_key)
        f.write(nonce)
        f.write(ciphertext)

    print(f"[+] Hybrid Encryption Succesful! ({asy_algo.upper()} + {sym_algo.upper()})")
    print(f"[+] Encrypted File: {out_path}")

def decrypt_file(filepath: str, out_path: str, privkey_path: str):
    # 1. Asimetrik Private Key'i Oku
    with open(privkey_path, "rb") as f:
        privkey_bytes = f.read()
    
    # 2. Dosya Başlığını (Metadata) Oku
    with open(filepath, "rb") as f:
        header = f.read(4)
        asy_id, sym_id, key_len = struct.unpack(">BBH", header)
        enc_key = f.read(key_len)
        nonce = f.read(12)
        ciphertext = f.read()

    privkey = serialization.load_pem_private_key(privkey_bytes, password=None)

    # 3. Kilitli Simetrik Parolayı Çöz
    if asy_id == 1: # RSA
        sym_key = privkey.decrypt(
            enc_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    elif asy_id == 2: # ECC
        # Karşı tarafın geçici public key'ini yükle
        eph_pub = serialization.load_pem_public_key(enc_key)
        # Kendi private key'in ile ortak sırrı oluştur
        shared_key = privkey.exchange(ec.ECDH(), eph_pub)
        # HKDF ile asıl AES/ChaCha20 anahtarını elde et
        sym_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid_ecc").derive(shared_key)

    # 4. Dosyayı Çöz (Metadata sayesinde AES mi ChaCha20 mi biliyoruz!)
    if sym_id == 1:
        cipher = AESGCM(sym_key)
        algo_name = "AES"
    else:
        cipher = ChaCha20Poly1305(sym_key)
        algo_name = "ChaCha20"
        
    data = cipher.decrypt(nonce, ciphertext, None)

    with open(out_path, "wb") as f:
        f.write(data)
        
    asy_name = "RSA" if asy_id == 1 else "ECC"
    print(f"[+] Hybrid Decryption Succesful! ({asy_name} + {algo_name} detected automatically)")
    print(f"[+] Decrypted File: {out_path}")