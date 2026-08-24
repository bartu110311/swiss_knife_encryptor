import hmac
import hashlib

def generate_hmac_text(text: str, secret_key: str) -> str:
    h = hmac.new(secret_key.encode('utf-8'), text.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

def generate_hmac_file(filepath: str, secret_key: str) -> str:
    h = hmac.new(secret_key.encode('utf-8'), digestmod=hashlib.sha256)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def verify_hmac_text(text: str, secret_key: str, expected_hmac: str) -> bool:
    calculated = generate_hmac_text(text, secret_key)
    return hmac.compare_digest(calculated, expected_hmac)

def verify_hmac_file(filepath: str, secret_key: str, expected_hmac: str) -> bool:
    calculated = generate_hmac_file(filepath, secret_key)
    return hmac.compare_digest(calculated, expected_hmac)