import random
import sys

PRIME = 2**521 - 1  # 521-bit Mersenne Asalı

def _eval_poly(poly, x):
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % PRIME
    return accum

def split_secret(secret_text: str, n: int, k: int) -> list:
    """Splits secret text into N shares with threshold K."""
    try:
        secret_bytes = secret_text.encode('utf-8')
        secret_int = int.from_bytes(secret_bytes, 'big')
        if secret_int >= PRIME:
            sys.exit("[-] Error: Secret text is too long for the prime modulus.")
        
        coeffs = [secret_int] + [random.randint(1, PRIME - 1) for _ in range(k - 1)]
        
        shares = []
        for i in range(1, n + 1):
            y = _eval_poly(coeffs, i)
            shares.append(f"{i}-{hex(y)[2:]}")
        return shares
    except Exception as e:
        sys.exit(f"[-] Error splitting secret: {e}")

def recover_secret(shares: list) -> str:
    """Recovers secret text from K shares using Lagrange Interpolation."""
    try:
        points = []
        for s in shares:
            x_str, y_str = s.split('-')
            points.append((int(x_str), int(y_str, 16)))
        
        secret_int = 0
        for i, (x_i, y_i) in enumerate(points):
            num, den = 1, 1
            for j, (x_j, _) in enumerate(points):
                if i == j:
                    continue
                num = (num * (-x_j)) % PRIME
                den = (den * (x_i - x_j)) % PRIME
            
            lagrange_i = (num * pow(den, PRIME - 2, PRIME)) % PRIME
            secret_int = (secret_int + y_i * lagrange_i) % PRIME
        
        byte_len = (secret_int.bit_length() + 7) // 8
        return secret_int.to_bytes(byte_len, 'big').decode('utf-8')
    except Exception as e:
        sys.exit(f"[-] Error recovering secret: {e}")