def encode_text(text: str) -> str:
    """Metni Hexadecimal (On altılık) formata çevirir."""
    return text.encode('utf-8').hex()

def decode_text(encoded_text: str) -> str:
    """Hex formatındaki metni normal metne çevirir."""
    return bytes.fromhex(encoded_text).decode('utf-8')

def encode_file(filepath: str, out_path: str):
    with open(filepath, "rb") as f:
        hex_data = f.read().hex()
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(hex_data)

def decode_file(filepath: str, out_path: str):
    with open(filepath, "r", encoding="utf-8") as f:
        hex_data = f.read().strip()
    with open(out_path, "wb") as f:
        f.write(bytes.fromhex(hex_data))