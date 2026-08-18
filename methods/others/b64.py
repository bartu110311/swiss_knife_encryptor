import base64

def encode_text(text: str) -> str:
    """Metni Base64 formatına çevirir."""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_text(encoded_text: str) -> str:
    """Base64 formatındaki metni normal metne çevirir."""
    return base64.b64decode(encoded_text).decode('utf-8')