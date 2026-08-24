import wave
import sys

def hide_text(audio_path: str, text: str, out_path: str):
    """Hides secret text in a WAV audio file using LSB steganography."""
    try:
        song = wave.open(audio_path, mode='rb')
        frame_bytes = bytearray(list(song.readframes(song.getnframes())))
        
        text_data = text + "===END==="
        bits = ''.join([format(ord(c), '08b') for c in text_data])

        if len(bits) > len(frame_bytes):
            sys.exit("[-] Error: Audio file is too small to hold this text.")

        for i, bit in enumerate(bits):
            frame_bytes[i] = (frame_bytes[i] & 254) | int(bit)

        with wave.open(out_path, 'wb') as fd:
            fd.setparams(song.getparams())
            fd.writeframes(bytes(frame_bytes))
        song.close()
        print(f"[+] Text hidden successfully in audio: {out_path}")
    except Exception as e:
        sys.exit(f"[-] Error in audio steganography hide: {e}")

def extract_text(audio_path: str) -> str:
    """Extracts hidden text from a WAV audio file."""
    try:
        song = wave.open(audio_path, mode='rb')
        frame_bytes = bytearray(list(song.readframes(song.getnframes())))
        song.close()

        extracted_bits = [str(frame_bytes[i] & 1) for i in range(len(frame_bytes))]
        extracted_bytes = [extracted_bits[i:i+8] for i in range(0, len(extracted_bits), 8)]

        decoded_chars = []
        for b in extracted_bytes:
            char = chr(int("".join(b), 2))
            decoded_chars.append(char)
            if "".join(decoded_chars).endswith("===END==="):
                return "".join(decoded_chars)[:-9]

        return "[-] No hidden text found or end marker missing."
    except Exception as e:
        sys.exit(f"[-] Error in audio steganography extract: {e}")