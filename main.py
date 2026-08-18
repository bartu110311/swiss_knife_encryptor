import argparse
import sys

__version__ = "0.2.0"

def main():
    parser = argparse.ArgumentParser(
        description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor/decryptor/hash verifier."
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- GENERATE KEYS COMMAND ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", help="Algorithm to generate keys for (e.g., rsa)")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (default: 2048)")

    # --- ENCRYPT COMMAND ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text or files")
    encrypt_parser.add_argument("algorithm", help="Encryption algorithm to use (e.g., aes, rsa)")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="Path of the file to encrypt")
    
    # Şifreleme parametreleri (Parola veya Public Key)
    encrypt_parser.add_argument("-p", "--password", help="Password for symmetric encryption (e.g., AES)")
    encrypt_parser.add_argument("--pubkey", help="Path to public key for asymmetric encryption (e.g., RSA)")
    encrypt_parser.add_argument("-b", "--bits", type=int, default=256, help="Key size in bits")

    # --- DECRYPT COMMAND ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text or files")
    decrypt_parser.add_argument("algorithm", help="Decryption algorithm to use")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="Path of the file to decrypt")
    
    # Çözme parametreleri (Parola veya Private Key)
    decrypt_parser.add_argument("-p", "--password", help="Password for symmetric decryption")
    decrypt_parser.add_argument("--privkey", help="Path to private key for asymmetric decryption")
    decrypt_parser.add_argument("-b", "--bits", type=int, default=256, help="Key size in bits")

    # --- HASH COMMAND ---
    hash_parser = subparsers.add_parser("hash", help="Generate or verify hashes")
    hash_parser.add_argument("algorithm", help="Hash algorithm to use (e.g., sha256)")
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
                sys.exit("[-] Error: AES requires a password (-p or --password).")
            from methods.sym.aes import encrypt_text
            if args.text:
                print(f"[+] AES Encrypted Text:\n    {encrypt_text(args.text, args.password, args.bits)}")
        
        elif args.algorithm.lower() == "rsa":
            if not args.pubkey:
                sys.exit("[-] Error: RSA requires a public key (--pubkey).")
            from methods.asy.rsa import encrypt_text
            if args.text:
                print(f"[+] RSA Encrypted Text:\n    {encrypt_text(args.text, args.pubkey)}")
            
    elif args.command == "decrypt":
        if args.algorithm.lower() == "aes":
            if not args.password:
                sys.exit("[-] Error: AES requires a password (-p or --password).")
            from methods.sym.aes import decrypt_text
            if args.text:
                try:
                    print(f"[+] Decrypted Text:\n    {decrypt_text(args.text, args.password, args.bits)}")
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

    elif args.command == "hash":
        if args.algorithm.lower() == "sha256":
            from methods.hash.sha256 import hash_text, hash_file
            if args.text:
                print(f"[+] SHA-256 Hash:\n    {hash_text(args.text)}")
            elif args.file:
                print(f"[+] File Hash:\n    {hash_file(args.file)}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()