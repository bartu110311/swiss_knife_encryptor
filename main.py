import argparse
import sys

__version__ = "0.1.0"

def main():
    parser = argparse.ArgumentParser(
        description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor/decryptor/hash verifier.",
        epilog="Use '%(prog)s <command> --help' for more information on a specific command."
    )
    
    parser.add_argument(
        "-v", "--version", 
        action="version", 
        version=f"%(prog)s v{__version__}",
        help="Show program's version number and exit."
    )

    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- ENCRYPT COMMAND ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text, files, or disks")
    encrypt_parser.add_argument("algorithm", help="Encryption algorithm to use (e.g., aes, caesar)")
    
    # --- DECRYPT COMMAND ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", help="Decryption algorithm to use")

    # --- HASH COMMAND ---
    hash_parser = subparsers.add_parser("hash", help="Generate or verify hashes")
    hash_parser.add_argument("algorithm", help="Hash algorithm to use (e.g., sha256, md5)")
    
    # Kullanıcı ya -t (text) ya da -f (file) girmek ZORUNDA. İkisi aynı anda girilemez.
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text", help="Text to hash")
    hash_group.add_argument("-f", "--file", help="Path of the file to hash")

    args = parser.parse_args()

    # --- ROUTING LOGIC ---
    if args.command == "encrypt":
        print(f"[*] Initializing {args.algorithm.upper()} encryption module... (Module not linked yet)")
        
    elif args.command == "decrypt":
        print(f"[*] Initializing {args.algorithm.upper()} decryption module... (Module not linked yet)")
        
    elif args.command == "hash":
        if args.algorithm.lower() == "sha256":
            from methods.hash.sha256_algo import hash_text, hash_file
            
            if args.text:
                result = hash_text(args.text)
                print(f"[+] SHA-256 Hash of '{args.text}':\n    {result}")
            
            elif args.file:
                try:
                    print(f"[*] Calculating SHA-256 hash for '{args.file}'...")
                    result = hash_file(args.file)
                    print(f"[+] File Hash:\n    {result}")
                except Exception as e:
                    print(f"[-] {e}")
        else:
            print(f"[-] Error: Hash algorithm '{args.algorithm}' is not supported yet.")
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()