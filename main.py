import argparse
import sys

__version__ = "0.4.0"

def main():
    parser = argparse.ArgumentParser(
        description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor/decryptor/hash/encoder."
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", help="Algorithm to generate keys for (e.g., rsa)")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (default: 2048)")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text or files")
    encrypt_parser.add_argument("algorithm", help="Encryption algorithm to use (e.g., aes, rsa)")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="Path of the file to encrypt")
    encrypt_parser.add_argument("-p", "--password", help="Password for symmetric encryption (e.g., AES)")
    encrypt_parser.add_argument("--pubkey", help="Path to public key for asymmetric encryption")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits for AES (default: 256)")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text or files")
    decrypt_parser.add_argument("algorithm", help="Decryption algorithm to use")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="Path of the file to decrypt")
    decrypt_parser.add_argument("-p", "--password", help="Password for symmetric decryption")
    decrypt_parser.add_argument("--privkey", help="Path to private key for asymmetric decryption")

    # --- ENCODE ---
    encode_parser = subparsers.add_parser("encode", help="Encode text (e.g., base64, hex)")
    encode_parser.add_argument("algorithm", help="Encoding algorithm")
    encode_group = encode_parser.add_mutually_exclusive_group(required=True)
    encode_group.add_argument("-t", "--text", help="Text to encode")

    # --- DECODE ---
    decode_parser = subparsers.add_parser("decode", help="Decode text (e.g., base64, hex)")
    decode_parser.add_argument("algorithm", help="Decoding algorithm")
    decode_group = decode_parser.add_mutually_exclusive_group(required=True)
    decode_group.add_argument("-t", "--text", help="Text to decode")

    # --- HASH ---
    hash_parser = subparsers.add_parser("hash", help="Generate or verify hashes")
    hash_parser.add_argument("algorithm", help="Hash algorithm to use (e.g., sha256, sha1)")
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text", help="Text to hash")
    hash_group.add_argument("-f", "--file", help="Path of the file to hash")

    args = parser.parse_args()

    # --- ROUTING LOGIC ---
    if args.command == "generate-keys":
        if args.algorithm.lower() == "rsa":
            from methods.asy.rsa import generate_keypair
            print(f"[*] Generating RSA-{args.bits} keypair...")
            generate_keypair(args.priv, args.pub, args.bits)
            print(f"[+] Success! Keys saved to '{args.pub}' and '{args.priv}'")
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported for key generation.")

    elif args.command == "encrypt":
        if args.algorithm.lower() == "aes":
            if not args.password:
                sys.exit("[-] Error: AES requires a password (-p).")
            from methods.sym.aes import encrypt_text
            if args.text:
                print(f"[+] AES-{args.bits} Encrypted Text:\n    {encrypt_text(args.text, args.password, args.bits)}")
        elif args.algorithm.lower() == "rsa":
            if not args.pubkey:
                sys.exit("[-] Error: RSA requires a public key (--pubkey).")
            from methods.asy.rsa import encrypt_text
            if args.text:
                print(f"[+] RSA Encrypted Text:\n    {encrypt_text(args.text, args.pubkey)}")
            
    elif args.command == "decrypt":
        if args.algorithm.lower() == "aes":
            if not args.password:
                sys.exit("[-] Error: AES requires a password (-p).")
            from methods.sym.aes import decrypt_text
            if args.text:
                try:
                    print(f"[+] Decrypted Text:\n    {decrypt_text(args.text, args.password)}")
                except Exception as e:
                    sys.exit(f"[-] {e}")
        elif args.algorithm.lower() == "rsa":
            if not args.privkey:
                sys.exit("[-] Error: RSA requires a private key (--privkey).")
            from methods.asy.rsa import decrypt_text
            if args.text:
                try:
                    print(f"[+] Decrypted Text:\n    {decrypt_text(args.text, args.privkey)}")
                except Exception as e:
                    sys.exit(f"[-] Decryption failed. Wrong key or corrupted data. Details: {e}")

    elif args.command == "encode":
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import encode_text
            if args.text:
                print(f"[+] Base64 Encoded:\n    {encode_text(args.text)}")
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import encode_text
            if args.text:
                print(f"[+] Hex Encoded:\n    {encode_text(args.text)}")
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported.")

    elif args.command == "decode":
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import decode_text
            if args.text:
                print(f"[+] Base64 Decoded:\n    {decode_text(args.text)}")
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import decode_text
            if args.text:
                try:
                    print(f"[+] Hex Decoded:\n    {decode_text(args.text)}")
                except Exception as e:
                    sys.exit(f"[-] Decode failed. Invalid hex string. Details: {e}")
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported.")

    elif args.command == "hash":
        if args.algorithm.lower() == "sha256":
            from methods.hash.sha256 import hash_text, hash_file
            if args.text:
                print(f"[+] SHA-256 Hash:\n    {hash_text(args.text)}")
            elif args.file:
                print(f"[+] File Hash:\n    {hash_file(args.file)}")
        elif args.algorithm.lower() == "sha1":
            from methods.hash.sha1 import hash_text, hash_file
            if args.text:
                print(f"[+] SHA-1 Hash:\n    {hash_text(args.text)}")
            elif args.file:
                print(f"[+] File Hash:\n    {hash_file(args.file)}")
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported yet.")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()