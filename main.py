import argparse
import sys

__version__ = "0.1.0"

def main():
    parser = argparse.ArgumentParser(
        description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor/decryptor/hash verifier."
    )
    
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- ENCRYPT COMMAND ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text or files")
    encrypt_parser.add_argument("algorithm", help="Encryption algorithm to use (e.g., aes)")
    
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="Path of the file to encrypt")
    
    encrypt_parser.add_argument("-p", "--password", required=True, help="Password for encryption")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits (default: 256)")

    # --- DECRYPT COMMAND ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text or files")
    decrypt_parser.add_argument("algorithm", help="Decryption algorithm to use (e.g., aes)")
    
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="Path of the file to decrypt")
    
    decrypt_parser.add_argument("-p", "--password", required=True, help="Password for decryption")
    decrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits (default: 256)")

    # --- HASH COMMAND ---
    hash_parser = subparsers.add_parser("hash", help="Generate or verify hashes")
    hash_parser.add_argument("algorithm", help="Hash algorithm to use (e.g., sha256)")
    
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text", help="Text to hash")
    hash_group.add_argument("-f", "--file", help="Path of the file to hash")

    args = parser.parse_args()

    # --- ROUTING LOGIC ---
    if args.command == "encrypt":
        if args.algorithm.lower() == "aes":
            from methods.sym.aes_algo import encrypt_text
            if args.text:
                result = encrypt_text(args.text, args.password, args.bits)
                print(f"[+] AES-{args.bits} Encrypted Text:\n    {result}")
            elif args.file:
                print("[-] File encryption is coming soon!")
        else:
            print(f"[-] Algorithm '{args.algorithm}' not supported yet.")
            
    elif args.command == "decrypt":
        if args.algorithm.lower() == "aes":
            from methods.sym.aes_algo import decrypt_text
            if args.text:
                try:
                    result = decrypt_text(args.text, args.password, args.bits)
                    print(f"[+] Decrypted Text:\n    {result}")
                except Exception as e:
                    print(f"[-] {e}")
            elif args.file:
                print("[-] File decryption is coming soon!")
        else:
            print(f"[-] Algorithm '{args.algorithm}' not supported yet.")
            
    elif args.command == "hash":
        if args.algorithm.lower() == "sha256":
            from methods.hash.sha256_algo import hash_text, hash_file
            if args.text:
                print(f"[+] SHA-256 Hash:\n    {hash_text(args.text)}")
            elif args.file:
                print(f"[+] File Hash:\n    {hash_file(args.file)}")
        else:
            print(f"[-] Algorithm '{args.algorithm}' not supported yet.")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()