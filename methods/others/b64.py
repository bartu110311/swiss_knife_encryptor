import base64

def encode_text(text: str) -> str:
    """Metni Base64 formatına çevirir."""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_text(encoded_text: str) -> str:
    """Base64 formatındaki metni normal metne çevirir."""
    return base64.b64decode(encoded_text).decode('utf-8')

def encode_file(filepath: str, out_path: str):
    with open(filepath, "rb") as f:
        encoded_bytes = base64.b64encode(f.read())
    with open(out_path, "wb") as f:
        f.write(encoded_bytes)

def decode_file(filepath: str, out_path: str):
    with open(filepath, "rb") as f:
        decoded_bytes = base64.b64decode(f.read())
    with open(out_path, "wb") as f:
        f.write(decoded_bytes)