import argparse
import sys

__version__ = "0.6.0"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one text/file/disk encryptor.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", help="Algorithm (e.g., rsa)")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text, files, or disks")
    encrypt_parser.add_argument("algorithm", help="Algorithm (aes, aes-xts, chacha20, rsa)")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="File to encrypt")
    enc_group.add_argument("-d", "--disk", help="Disk/Device path to encrypt IN-PLACE")
    encrypt_parser.add_argument("-o", "--out", help="Output file path (required for -f)")
    encrypt_parser.add_argument("--header", help="Detached header path (required for -d disk operations)")
    encrypt_parser.add_argument("-p", "--password", help="Password for symmetric encryption")
    encrypt_parser.add_argument("--pubkey", help="Path to public key for RSA")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size for AES")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", help="Algorithm (aes, aes-xts, chacha20, rsa)")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="File to decrypt")
    dec_group.add_argument("-d", "--disk", help="Disk/Device path to decrypt IN-PLACE")
    decrypt_parser.add_argument("-o", "--out", help="Output file path (required for -f)")
    decrypt_parser.add_argument("--header", help="Detached header path (required for -d disk operations)")
    decrypt_parser.add_argument("-p", "--password", help="Password for symmetric decryption")
    decrypt_parser.add_argument("--privkey", help="Path to private key for RSA")

    # --- ENCODE / DECODE / HASH (Kısalttım, öncekiyle aynı) ---
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument("algorithm")
    encd_grp = encode_parser.add_mutually_exclusive_group(required=True)
    encd_grp.add_argument("-t", "--text")
    encd_grp.add_argument("-f", "--file")
    encode_parser.add_argument("-o", "--out")

    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("algorithm")
    decd_grp = decode_parser.add_mutually_exclusive_group(required=True)
    decd_grp.add_argument("-t", "--text")
    decd_grp.add_argument("-f", "--file")
    decode_parser.add_argument("-o", "--out")

    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument("algorithm")
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text")
    hash_group.add_argument("-f", "--file")

    args = parser.parse_args()

    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    if args.command == "generate-keys":
        if args.algorithm.lower() == "rsa":
            from methods.asy.rsa import generate_keypair
            generate_keypair(args.priv, args.pub, args.bits)
            print("[+] RSA Keys generated.")

    elif args.command == "encrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Disk encryption requires --header and -p (password).")
            if args.algorithm.lower() == "aes-xts":
                from methods.sym import aes_xts
                from utils.disk import process_disk
                process_disk(args.disk, args.header, args.password, "encrypt", aes_xts, args.bits)
            else:
                sys.exit("[-] Disk operations currently only support aes-xts.")
        else:
            check_file_output(args)
            if args.algorithm.lower() == "aes":
                from methods.sym.aes import encrypt_text, encrypt_file
                if args.text: print(encrypt_text(args.text, args.password, args.bits))
                elif args.file: encrypt_file(args.file, args.out, args.password, args.bits)
            elif args.algorithm.lower() == "chacha20":
                from methods.sym.chacha20 import encrypt_text, encrypt_file
                if args.text: print(encrypt_text(args.text, args.password))
                elif args.file: encrypt_file(args.file, args.out, args.password)
            elif args.algorithm.lower() == "rsa":
                from methods.asy.rsa import encrypt_text, encrypt_file
                if args.text: print(encrypt_text(args.text, args.pubkey))
                elif args.file: encrypt_file(args.file, args.out, args.pubkey)

    elif args.command == "decrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Disk decryption requires --header and -p (password).")
            if args.algorithm.lower() == "aes-xts":
                from methods.sym import aes_xts
                from utils.disk import process_disk
                process_disk(args.disk, args.header, args.password, "decrypt", aes_xts)
            else:
                sys.exit("[-] Disk operations currently only support aes-xts.")
        else:
            check_file_output(args)
            if args.algorithm.lower() == "aes":
                from methods.sym.aes import decrypt_text, decrypt_file
                if args.text: print(decrypt_text(args.text, args.password))
                elif args.file: decrypt_file(args.file, args.out, args.password)
            elif args.algorithm.lower() == "chacha20":
                from methods.sym.chacha20 import decrypt_text, decrypt_file
                if args.text: print(decrypt_text(args.text, args.password))
                elif args.file: decrypt_file(args.file, args.out, args.password)
            elif args.algorithm.lower() == "rsa":
                from methods.asy.rsa import decrypt_text, decrypt_file
                if args.text: print(decrypt_text(args.text, args.privkey))
                elif args.file: decrypt_file(args.file, args.out, args.privkey)

    # Encode, Decode, Hash logic remains identical to previous version
    elif args.command == "encode":
        check_file_output(args)
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import encode_text, encode_file
            if args.text: print(encode_text(args.text))
            elif args.file: encode_file(args.file, args.out)
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import encode_text, encode_file
            if args.text: print(encode_text(args.text))
            elif args.file: encode_file(args.file, args.out)

    elif args.command == "decode":
        check_file_output(args)
        if args.algorithm.lower() in ["base64", "b64"]:
            from methods.others.b64 import decode_text, decode_file
            if args.text: print(decode_text(args.text))
            elif args.file: decode_file(args.file, args.out)
        elif args.algorithm.lower() == "hex":
            from methods.others.hexcode import decode_text, decode_file
            if args.text: print(decode_text(args.text))
            elif args.file: decode_file(args.file, args.out)

    elif args.command == "hash":
        if args.algorithm.lower() == "sha256": from methods.hash.sha256 import hash_text, hash_file
        elif args.algorithm.lower() == "sha1": from methods.hash.sha1 import hash_text, hash_file
        elif args.algorithm.lower() == "sha512": from methods.hash.sha512 import hash_text, hash_file
        if args.text: print(hash_text(args.text))
        elif args.file: print(hash_file(args.file))

if __name__ == "__main__":
    main()