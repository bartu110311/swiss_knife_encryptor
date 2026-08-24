import base64
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Kuznyechik Pi (S-box) dönüşüm tablosu
PI = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x2A, 0x61, 0x86, 0x58, 0x53, 0x9E, 0x59, 0x46, 0x0B, 0xAF, 0x4B, 0xCA, 0xBE, 0x41,
    0x44, 0x6D, 0x8A, 0x0F, 0x96, 0x6B, 0x85, 0x07, 0x6F, 0x02, 0x72, 0x7A, 0xAC, 0x66, 0xFD, 0x9F,
    0x30, 0x4A, 0x0D, 0x5D, 0xDE, 0x7D, 0xED, 0x20, 0xE7, 0xB8, 0x71, 0x5B, 0x63, 0xEE, 0x0C, 0x8A,
    0x0A, 0x08, 0x13, 0x91, 0x00, 0xEE, 0xFE, 0x27, 0x25, 0x2B, 0x7E, 0xBE, 0x47, 0x4A, 0x15, 0x40,
    0x06, 0xC3, 0xB3, 0x92, 0x97, 0x50, 0x67, 0x62, 0x48, 0xE0, 0x52, 0x9C, 0x56, 0xEC, 0x24, 0xE6,
    0x2D, 0x2F, 0x9D, 0x7C, 0x4F, 0x82, 0x19, 0xAB, 0xC0, 0x0A, 0x3A, 0x83, 0x78, 0x2C, 0x9A, 0x55,
    0x09, 0xC8, 0xC9, 0x4E, 0x45, 0x54, 0xCE, 0x0E, 0x7F, 0x03, 0x6A, 0x10, 0x73, 0x70, 0x80, 0xE5,
    0x6C, 0x7B, 0xA8, 0x22, 0x29, 0x28, 0x60, 0x49, 0xB2, 0x3F, 0x26, 0x32, 0x0E, 0x76, 0x88, 0x12,
    0x8F, 0x1D, 0x87, 0x57, 0x33, 0x35, 0x43, 0x1F, 0x89, 0xF4, 0x5E, 0x9B, 0x1E, 0x95, 0x90, 0x11,
    0x69, 0x8D, 0x8C, 0xA1, 0x37, 0xD7, 0x94, 0x68, 0x98, 0xFF, 0x4C, 0xC7, 0xD3, 0xC2, 0x34, 0x24,
    0x1A, 0x79, 0x38, 0x1B, 0x3E, 0x75, 0xB9, 0x74, 0x2D, 0xDA, 0x5D, 0xD1, 0x51, 0xDC, 0x0E, 0x8D,
    0xC6, 0xD0, 0xD2, 0x4B, 0x25, 0xD5, 0xD4, 0xEC, 0xD6, 0xDF, 0xE1, 0xE3, 0xE4, 0xE8, 0xEA, 0xEB,
    0xF2, 0xF3, 0xF5, 0xF6, 0xF7, 0xF8, 0xBC, 0xBD, 0xD8, 0xD9, 0x39, 0x3D, 0xA0, 0xA2, 0xA3, 0xA4
]
PI_INV = [PI.index(i) for i in range(256)]

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode("utf-8"))

def _kuznyechik_block_encrypt(block: bytes, key: bytes) -> bytes:
    # SPN tabanlı basitleştirilmiş Kuznyechik tur fonksiyonu
    state = bytearray(block)
    for r in range(10):
        # AddRoundKey
        for i in range(16):
            state[i] ^= key[(r * 16 + i) % 32]
        # SubBytes (Pi)
        if r < 9:
            for i in range(16):
                state[i] = PI[state[i]]
    return bytes(state)

def _kuznyechik_block_decrypt(block: bytes, key: bytes) -> bytes:
    state = bytearray(block)
    for r in range(9, -1, -1):
        if r < 9:
            for i in range(16):
                state[i] = PI_INV[state[i]]
        for i in range(16):
            state[i] ^= key[(r * 16 + i) % 32]
    return bytes(state)

def encrypt_text(text: str, password: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = _derive_key(password, salt)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode("utf-8")) + padder.finalize()
    
    ct = bytearray()
    prev = iv
    for i in range(0, len(padded_data), 16):
        block = bytes(b ^ p for b, p in zip(padded_data[i:i+16], prev))
        enc_block = _kuznyechik_block_encrypt(block, key)
        ct.extend(enc_block)
        prev = enc_block
        
    return base64.b64encode(salt + iv + ct).decode("utf-8")

def decrypt_text(cipher_text: str, password: str) -> str:
    raw = base64.b64decode(cipher_text.encode("utf-8"))
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = _derive_key(password, salt)
    
    pt = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        curr_ct = ct[i:i+16]
        dec_block = _kuznyechik_block_decrypt(curr_ct, key)
        pt.extend(bytes(d ^ p for d, p in zip(dec_block, prev)))
        prev = curr_ct
        
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(pt) + unpadder.finalize()
    return data.decode("utf-8")

def encrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, "rb") as f:
        data = f.read()
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = _derive_key(password, salt)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    ct = bytearray()
    prev = iv
    for i in range(0, len(padded_data), 16):
        block = bytes(b ^ p for b, p in zip(padded_data[i:i+16], prev))
        enc_block = _kuznyechik_block_encrypt(block, key)
        ct.extend(enc_block)
        prev = enc_block
        
    with open(output_path, "wb") as f:
        f.write(salt + iv + ct)

def decrypt_file(input_path: str, output_path: str, password: str):
    with open(input_path, "rb") as f:
        raw = f.read()
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = _derive_key(password, salt)
    
    pt = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        curr_ct = ct[i:i+16]
        dec_block = _kuznyechik_block_decrypt(curr_ct, key)
        pt.extend(bytes(d ^ p for d, p in zip(dec_block, prev)))
        prev = curr_ct
        
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(pt) + unpadder.finalize()
    
    with open(output_path, "wb") as f:
        f.write(data)