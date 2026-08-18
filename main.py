import argparse
import sys

__version__ = "0.5.0"

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
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text or files")
    encrypt_parser.add_argument("algorithm", help="Encryption algorithm to use")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="Path of the file to encrypt")
    encrypt_parser.add_argument("-o", "--out", help="Output file path (required if using -f)")
    encrypt_parser.add_argument("-p", "--password", help="Password for symmetric encryption")
    encrypt_parser.add_argument("--pubkey", help="Path to public key for asymmetric encryption")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size for AES")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text or files")
    decrypt_parser.add_argument("algorithm", help="Decryption algorithm to use")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="Path of the file to decrypt")
    decrypt_parser.add_argument("-o", "--out", help="Output file path (required if using -f)")
    decrypt_parser.add_argument("-p", "--password", help="Password for symmetric decryption")
    decrypt_parser.add_argument("--privkey", help="Path to private key for asymmetric decryption")

    # --- ENCODE ---
    encode_parser = subparsers.add_parser("encode", help="Encode text or files")
    encode_parser.add_argument("algorithm", help="Encoding algorithm")
    encode_group = encode_parser.add_mutually_exclusive_group(required=True)
    encode_group.add_argument("-t", "--text", help="Text to encode")
    encode_group.add_argument("-f", "--file", help="Path of the file to encode")
    encode_parser.add_argument("-o", "--out", help="Output file path")

    # --- DECODE ---
    decode_parser = subparsers.add_parser("decode", help="Decode text or files")
    decode_parser.add_argument("algorithm", help="Decoding algorithm")
    decode_group = decode_parser.add_mutually_exclusive_group(required=True)
    decode_group.add_argument("-t", "--text", help="Text to decode")
    decode_group.add_argument("-f", "--file", help="Path of the file to decode")
    decode_parser.add_argument("-o", "--out", help="Output file path")

    # --- HASH ---
    hash_parser = subparsers.add_parser("hash", help="Generate or verify hashes")
    hash_parser.add_argument("algorithm", help="Hash algorithm (sha256, sha1, sha512)")
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text", help="Text to hash")
    hash_group.add_argument("-f", "--file", help="Path of the file to hash")

    args = parser.parse_args()

    # YARDIMCI FONKSİYON: Dosya işlemleri için -o parametresi kontrolü
    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    # --- ROUTING LOGIC ---
    if args.command == "generate-keys":
        if args.algorithm.lower() == "rsa":
            from methods.asy.rsa import generate_keypair
            generate_keypair(args.priv, args.pub, args.bits)
            print(f"[+] Success! Keys saved to '{args.pub}' and '{args.priv}'")
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported.")

    elif args.command == "encrypt":
        check_file_output(args)
        if args.algorithm.lower() == "aes":
            if not args.password:
                sys.exit("[-] Error: AES requires a password (-p).")
            from methods.sym.aes import encrypt_text, encrypt_file
            if args.text:
                print(f"[+] Encrypted:\n    {encrypt_text(args.text, args.password, args.bits)}")
            elif args.file:
                encrypt_file(args.file, args.out, args.password, args.bits)
                print(f"[+] Success! Encrypted file saved to '{args.out}'")
                
        elif args.algorithm.lower() == "rsa":
            if not args.pubkey:
                sys.exit("[-] Error: RSA requires a public key (--pubkey).")
            from methods.asy.rsa import encrypt_text, encrypt_file
            if args.text:
                print(f"[+] Encrypted:\n    {encrypt_text(args.text, args.pubkey)}")
            elif args.file:
                try:
                    encrypt_file(args.file, args.out, args.pubkey)
                    print(f"[+] Success! Encrypted file saved to '{args.out}'")
                except ValueError as e:
                    sys.exit(f"[-] RSA Error: Data too large for key size. Use AES for large files. Details: {e}")
            
    elif args.command == "decrypt":
        check_file_output(args)
        if args.algorithm.lower() == "aes":
            if not args.password:
                sys.exit("[-] Error: AES requires a password (-p).")
            from methods.sym.aes import decrypt_text, decrypt_file
            if args.text:
                print(f"[+] Decrypted:\n    {decrypt_text(args.text, args.password)}")
            elif args.file:
                decrypt_file(args.file, args.out, args.password)
                print(f"[+] Success! Decrypted file saved to '{args.out}'")
                
        elif args.algorithm.lower() == "rsa":
            if not args.privkey:
                sys.exit("[-] Error: RSA requires a private key (--privkey).")
            from methods.asy.rsa import decrypt_text, decrypt_file
            if args.text:
                print(f"[+] Decrypted:\n    {decrypt_text(args.text, args.privkey)}")
            elif args.file:
                decrypt_file(args.file, args.out, args.privkey)
                print(f"[+] Success! Decrypted file saved to '{args.out}'")

    elif args.command == "encode":
        check_file_output(args)
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import encode_text, encode_file
            if args.text:
                print(f"[+] Encoded:\n    {encode_text(args.text)}")
            elif args.file:
                encode_file(args.file, args.out)
                print(f"[+] Success! Encoded file saved to '{args.out}'")
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import encode_text, encode_file
            if args.text:
                print(f"[+] Encoded:\n    {encode_text(args.text)}")
            elif args.file:
                encode_file(args.file, args.out)
                print(f"[+] Success! Encoded file saved to '{args.out}'")

    elif args.command == "decode":
        check_file_output(args)
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import decode_text, decode_file
            if args.text:
                print(f"[+] Decoded:\n    {decode_text(args.text)}")
            elif args.file:
                decode_file(args.file, args.out)
                print(f"[+] Success! Decoded file saved to '{args.out}'")
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import decode_text, decode_file
            if args.text:
                print(f"[+] Decoded:\n    {decode_text(args.text)}")
            elif args.file:
                decode_file(args.file, args.out)
                print(f"[+] Success! Decoded file saved to '{args.out}'")

    elif args.command == "hash":
        if args.algorithm.lower() == "sha256":
            from methods.hash.sha256 import hash_text, hash_file
        elif args.algorithm.lower() == "sha1":
            from methods.hash.sha1 import hash_text, hash_file
        elif args.algorithm.lower() == "sha512":
            from methods.hash.sha512 import hash_text, hash_file
        else:
            sys.exit(f"[-] Algorithm '{args.algorithm}' not supported yet.")
            
        if args.text:
            print(f"[+] Hash:\n    {hash_text(args.text)}")
        elif args.file:
            print(f"[+] File Hash:\n    {hash_file(args.file)}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()