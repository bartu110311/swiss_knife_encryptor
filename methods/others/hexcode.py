def encode_text(text: str) -> str:
    """Metni Hexadecimal (On altılık) formata çevirir."""
    return text.encode('utf-8').hex()

def decode_text(encoded_text: str) -> str:
    """Hex formatındaki metni normal metne çevirir."""
    return bytes.fromhex(encoded_text).decode('utf-8')