from PIL import Image
import os

def _text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def _binary_to_text(binary_str):
    chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return ''.join(chr(int(char, 2)) for char in chars if int(char, 2) != 0)

def hide_text(image_path: str, secret_text: str, out_path: str):
    """Hides a secret text inside an image."""
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        
        # Add a delimiter so we know where the text ends when extracting
        secret_text += "======END======"
        binary_secret = _text_to_binary(secret_text)
        
        if len(binary_secret) > len(pixels) * 3:
            print("[-] ERROR: Image is too small to hold this much data!")
            return

        new_pixels = []
        bit_index = 0
        
        for pixel in pixels:
            r, g, b = pixel
            
            if bit_index < len(binary_secret):
                r = (r & ~1) | int(binary_secret[bit_index])
                bit_index += 1
            if bit_index < len(binary_secret):
                g = (g & ~1) | int(binary_secret[bit_index])
                bit_index += 1
            if bit_index < len(binary_secret):
                b = (b & ~1) | int(binary_secret[bit_index])
                bit_index += 1
                
            new_pixels.append((r, g, b))
            
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(out_path, format="PNG")
        print(f"[+] SUCCESS: Secret text hidden successfully in {out_path}")
        
    except Exception as e:
        print(f"[-] ERROR hiding text: {e}")

def extract_text(image_path: str) -> str:
    """Extracts hidden text from an image."""
    try:
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        
        binary_secret = ""
        for pixel in pixels:
            r, g, b = pixel
            binary_secret += str(r & 1)
            binary_secret += str(g & 1)
            binary_secret += str(b & 1)
            
        extracted_text = _binary_to_text(binary_secret)
        
        if "======END======" in extracted_text:
            secret = extracted_text.split("======END======")[0]
            print(f"[+] EXTRACTED SECRET: {secret}")
            return secret
        else:
            print("[-] WARNING: No hidden message found or image is corrupted/compressed.")
            return ""
            
    except Exception as e:
        print(f"[-] ERROR extracting text: {e}")
        return ""