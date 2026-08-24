import hashlib
import os
import sys
from twofish import Twofish

BLOCK_SIZE = 16

def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def encrypt_text(text: str, password: str) -> str:
    """Encrypts plaintext using Twofish in CBC mode."""
    try:
        key = hashlib.sha256(password.encode()).digest()
        iv = os.urandom(BLOCK_SIZE)
        data = _pad(text.encode('utf-8'))
        
        tf = Twofish(key)
        cipher_bytes = bytearray()
        prev_block = iv
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted_block = tf.encrypt(xored)
            cipher_bytes.extend(encrypted_block)
            prev_block = encrypted_block
            
        return (iv + bytes(cipher_bytes)).hex()
    except Exception as e:
        sys.exit(f"[-] Error encrypting with Twofish: {e}")

def decrypt_text(cipher_hex: str, password: str) -> str:
    """Decrypts Twofish CBC encrypted hex string."""
    try:
        raw = bytes.fromhex(cipher_hex)
        iv = raw[:BLOCK_SIZE]
        cipher_data = raw[BLOCK_SIZE:]
        key = hashlib.sha256(password.encode()).digest()
        
        tf = Twofish(key)
        plain_bytes = bytearray()
        prev_block = iv
        
        for i in range(0, len(cipher_data), BLOCK_SIZE):
            block = cipher_data[i:i+BLOCK_SIZE]
            decrypted_block = tf.decrypt(block)
            xored = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plain_bytes.extend(xored)
            prev_block = block
            
        return _unpad(bytes(plain_bytes)).decode('utf-8')
    except Exception as e:
        sys.exit(f"[-] Error decrypting with Twofish: {e}")

def encrypt_file(in_path: str, out_path: str, password: str):
    """Encrypts a file using Twofish in CBC mode."""
    try:
        with open(in_path, 'rb') as f:
            data = f.read()
        key = hashlib.sha256(password.encode()).digest()
        iv = os.urandom(BLOCK_SIZE)
        padded_data = _pad(data)
        
        tf = Twofish(key)
        cipher_bytes = bytearray()
        prev_block = iv
        
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted_block = tf.encrypt(xored)
            cipher_bytes.extend(encrypted_block)
            prev_block = encrypted_block
            
        with open(out_path, 'wb') as f:
            f.write(iv + bytes(cipher_bytes))
        print(f"[+] File encrypted with Twofish: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error encrypting file with Twofish: {e}")

def decrypt_file(in_path: str, out_path: str, password: str):
    """Decrypts a file encrypted with Twofish CBC."""
    try:
        with open(in_path, 'rb') as f:
            raw = f.read()
        iv = raw[:BLOCK_SIZE]
        cipher_data = raw[BLOCK_SIZE:]
        key = hashlib.sha256(password.encode()).digest()
        
        tf = Twofish(key)
        plain_bytes = bytearray()
        prev_block = iv
        
        for i in range(0, len(cipher_data), BLOCK_SIZE):
            block = cipher_data[i:i+BLOCK_SIZE]
            decrypted_block = tf.decrypt(block)
            xored = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plain_bytes.extend(xored)
            prev_block = block
            
        unpadded = _unpad(bytes(plain_bytes))
        with open(out_path, 'wb') as f:
            f.write(unpadded)
        print(f"[+] File decrypted with Twofish: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error decrypting file with Twofish: {e}")