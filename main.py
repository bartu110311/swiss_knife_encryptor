import argparse
import sys

__version__ = "0.1.0"

def main():
    # 1. Main Parser Setup
    parser = argparse.ArgumentParser(
        description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor/decryptor/hash verifier.",
        epilog="Use '%(prog)s <command> --help' for more information on a specific command."
    )
    
    # Version argument
    parser.add_argument(
        "-v", "--version", 
        action="version", 
        version=f"%(prog)s v{__version__}",
        help="Show program's version number and exit."
    )

    # 2. Subparsers Setup (Routing)
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

    # 3. Parse Arguments
    args = parser.parse_args()

    # 4. Command Routing Logic
    if args.command == "encrypt":
        print(f"[*] Initializing {args.algorithm.upper()} encryption module... (Module not linked yet)")
        # Future: import ciphers.aes; ciphers.aes.encrypt(...)
        
    elif args.command == "decrypt":
        print(f"[*] Initializing {args.algorithm.upper()} decryption module... (Module not linked yet)")
        
    elif args.command == "hash":
        print(f"[*] Initializing {args.algorithm.upper()} hashing module... (Module not linked yet)")
        
    else:
        # If user runs the script without any arguments
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()