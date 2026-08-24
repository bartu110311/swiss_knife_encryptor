import json
import math
import secrets

def _is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
        
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p

def _mod_inverse(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Modular reverse is not available.")
    return x % m

def generate_keypair(priv_path, pub_path, bits=2048):
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    while p == q:
        q = _generate_prime(bits // 2)
        
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    g = n + 1
    
    l_val = (pow(g, lam, n * n) - 1) // n
    mu = _mod_inverse(l_val, n)
    
    pub_key = {"n": n, "g": g}
    priv_key = {"lam": lam, "mu": mu, "n": n}
    
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump(pub_key, f, indent=4)
        
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(priv_key, f, indent=4)
        
    print(f"[+] Paillier key pair is created: {pub_path}, {priv_path}")

def encrypt_text(text, pub_key_path):
    with open(pub_key_path, "r", encoding="utf-8") as f:
        pub_key = json.load(f)
        
    n = pub_key["n"]
    g = pub_key["g"]
    n_sq = n * n
    
    m = int.from_bytes(text.encode("utf-8"), byteorder="big")
    if m >= n:
        raise ValueError("The text size cannot exceed the Paillier modulus value (n).")
        
    r = secrets.randbelow(n - 1) + 1
    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1
        
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return str(c)

def decrypt_text(cipher_text, priv_key_path):
    with open(priv_key_path, "r", encoding="utf-8") as f:
        priv_key = json.load(f)
        
    n = priv_key["n"]
    lam = priv_key["lam"]
    mu = priv_key["mu"]
    n_sq = n * n
    
    c = int(cipher_text.strip())
    l_val = (pow(c, lam, n_sq) - 1) // n
    m = (l_val * mu) % n
    
    byte_len = (m.bit_length() + 7) // 8
    return m.to_bytes(byte_len, byteorder="big").decode("utf-8")

def encrypt_file(input_path, output_path, pub_key_path):
    with open(input_path, "rb") as f:
        content = f.read().decode("utf-8", errors="ignore")
    cipher = encrypt_text(content, pub_key_path)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(cipher)

def decrypt_file(input_path, output_path, priv_key_path):
    with open(input_path, "r", encoding="utf-8") as f:
        cipher = f.read()
    plain = decrypt_text(cipher, priv_key_path)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(plain)