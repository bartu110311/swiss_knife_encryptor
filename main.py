import argparse
import sys

__version__ = "0.6.1"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor & hybrid engine.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Algorithm (rsa or ecc)")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (for RSA)")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text, files, or disks")
    encrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "rsa", "hybrid"], help="Algorithm")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="File to encrypt")
    enc_group.add_argument("-d", "--disk", help="Disk/Device path to encrypt IN-PLACE")
    
    encrypt_parser.add_argument("-o", "--out", help="Output file path (required for -f)")
    encrypt_parser.add_argument("--header", help="Detached header path (for disk operations)")
    encrypt_parser.add_argument("-p", "--password", help="Password for symmetric encryption")
    encrypt_parser.add_argument("--pubkey", help="Path to public key (for RSA/Hybrid)")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size for AES")
    
    # Hybrid için özel parametreler
    encrypt_parser.add_argument("--asy", choices=["rsa", "ecc"], help="Hybrid for: Asymmetric algorithm")
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20"], help="Hybrid for: Symmetric algorithm")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "rsa", "hybrid"], help="Algorithm")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="File to decrypt")
    dec_group.add_argument("-d", "--disk", help="Disk/Device path to decrypt IN-PLACE")
    
    decrypt_parser.add_argument("-o", "--out", help="Output file path (required for -f)")
    decrypt_parser.add_argument("--header", help="Detached header path (for disk operations)")
    decrypt_parser.add_argument("-p", "--password", help="Password for symmetric decryption")
    decrypt_parser.add_argument("--privkey", help="Path to private key (for RSA/Hybrid)")

    # --- ENCODE ---
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    encd_grp = encode_parser.add_mutually_exclusive_group(required=True)
    encd_grp.add_argument("-t", "--text")
    encd_grp.add_argument("-f", "--file")
    encode_parser.add_argument("-o", "--out")

    # --- DECODE ---
    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    decd_grp = decode_parser.add_mutually_exclusive_group(required=True)
    decd_grp.add_argument("-t", "--text")
    decd_grp.add_argument("-f", "--file")
    decode_parser.add_argument("-o", "--out")

    # --- HASH ---
    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument("algorithm", choices=["sha1", "sha256", "sha512"])
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text")
    hash_group.add_argument("-f", "--file")

    args = parser.parse_args()

    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    # --- ROUTING LOGIC ---
    if args.command == "generate-keys":
        if args.algorithm == "rsa":
            from methods.asy import rsa
            rsa.generate_keypair(args.priv, args.pub, args.bits)
            print("[+] RSA Keys generated.")
        elif args.algorithm == "ecc":
            from methods.asy import ecc
            ecc.generate_keypair(args.priv, args.pub)

    elif args.command == "encrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Disk encryption requires --header and -p (password).")
            if args.algorithm == "aes-xts":
                from methods.sym import aes_xts
                from utils.disk import process_disk
                process_disk(args.disk, args.header, args.password, "encrypt", aes_xts, args.bits)
            else:
                sys.exit("[-] Disk operations currently only support aes-xts.")
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes
                if not args.password: sys.exit("[-] AES requires -p password.")
                if args.text: print(aes.encrypt_text(args.text, args.password, args.bits))
                elif args.file: aes.encrypt_file(args.file, args.out, args.password, args.bits)
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20
                if not args.password: sys.exit("[-] ChaCha20 requires -p password.")
                if args.text: print(chacha20.encrypt_text(args.text, args.password))
                elif args.file: chacha20.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "rsa":
                from methods.asy import rsa
                if not args.pubkey: sys.exit("[-] RSA requires --pubkey.")
                if args.text: print(rsa.encrypt_text(args.text, args.pubkey))
                elif args.file: rsa.encrypt_file(args.file, args.out, args.pubkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                if not args.pubkey or not args.asy or not args.sym:
                    sys.exit("[-] Hybrid encryption requires --pubkey, --asy and --sym.")
                if args.text:
                    sys.exit("[-] Hybrid encryption is currently for files only (-f).")
                hybrid_engine.encrypt_file(args.file, args.out, args.pubkey, args.asy, args.sym)

    elif args.command == "decrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Disk decryption requires --header and -p (password).")
            if args.algorithm == "aes-xts":
                from methods.sym import aes_xts
                from utils.disk import process_disk
                process_disk(args.disk, args.header, args.password, "decrypt", aes_xts)
            else:
                sys.exit("[-] Disk operations currently only support aes-xts.")
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes
                if not args.password: sys.exit("[-] AES requires -p password.")
                if args.text: print(aes.decrypt_text(args.text, args.password))
                elif args.file: aes.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20
                if not args.password: sys.exit("[-] ChaCha20 requires -p password.")
                if args.text: print(chacha20.decrypt_text(args.text, args.password))
                elif args.file: chacha20.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "rsa":
                from methods.asy import rsa
                if not args.privkey: sys.exit("[-] RSA requires --privkey.")
                if args.text: print(rsa.decrypt_text(args.text, args.privkey))
                elif args.file: rsa.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                if not args.privkey:
                    sys.exit("[-] Hybrid decryption requires --privkey.")
                if args.text:
                    sys.exit("[-] Hybrid decryption is currently for files only (-f).")
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)

    elif args.command == "encode":
        check_file_output(args)
        if args.algorithm in ["base64", "b64"]:
            from methods.others import b64
            if args.text: print(b64.encode_text(args.text))
            elif args.file: b64.encode_file(args.file, args.out)
        elif args.algorithm == "hex":
            from methods.others import hexcode
            if args.text: print(hexcode.encode_text(args.text))
            elif args.file: hexcode.encode_file(args.file, args.out)

    elif args.command == "decode":
        check_file_output(args)
        if args.algorithm in ["base64", "b64"]:
            from methods.others import b64
            if args.text: print(b64.decode_text(args.text))
            elif args.file: b64.decode_file(args.file, args.out)
        elif args.algorithm == "hex":
            from methods.others import hexcode
            if args.text: print(hexcode.decode_text(args.text))
            elif args.file: hexcode.decode_file(args.file, args.out)

    elif args.command == "hash":
        if args.algorithm == "sha1":
            from methods.hash import sha1 as hash_module
        elif args.algorithm == "sha256":
            from methods.hash import sha256 as hash_module
        elif args.algorithm == "sha512":
            from methods.hash import sha512 as hash_module
            
        if args.text: print(hash_module.hash_text(args.text))
        elif args.file: print(hash_module.hash_file(args.file))

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()