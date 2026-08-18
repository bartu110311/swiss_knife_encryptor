import argparse
import sys

__version__ = "0.6.2"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one cryptosystem.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Algorithm")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (for RSA)")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text, files, or disks")
    encrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "camellia", "rsa", "hybrid"])
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text")
    enc_group.add_argument("-f", "--file")
    enc_group.add_argument("-d", "--disk")
    
    encrypt_parser.add_argument("-o", "--out")
    encrypt_parser.add_argument("--header")
    encrypt_parser.add_argument("-p", "--password")
    encrypt_parser.add_argument("--pubkey")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256)
    
    encrypt_parser.add_argument("--asy", choices=["rsa", "ecc"], help="Hybrid ASY algorithm")
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20"], help="Hybrid SYM algorithm")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "camellia", "rsa", "hybrid"])
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text")
    dec_group.add_argument("-f", "--file")
    dec_group.add_argument("-d", "--disk")
    
    decrypt_parser.add_argument("-o", "--out")
    decrypt_parser.add_argument("--header")
    decrypt_parser.add_argument("-p", "--password")
    decrypt_parser.add_argument("--privkey")
    decrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256)

    # --- ENCODE / DECODE ---
    encode_parser = subparsers.add_parser("encode")
    encode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    encd_grp = encode_parser.add_mutually_exclusive_group(required=True)
    encd_grp.add_argument("-t", "--text")
    encd_grp.add_argument("-f", "--file")
    encode_parser.add_argument("-o", "--out")

    decode_parser = subparsers.add_parser("decode")
    decode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    decd_grp = decode_parser.add_mutually_exclusive_group(required=True)
    decd_grp.add_argument("-t", "--text")
    decd_grp.add_argument("-f", "--file")
    decode_parser.add_argument("-o", "--out")

    # --- HASH ---
    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument("algorithm", choices=["sha1", "sha256", "sha512", "blake2b", "blake2s"])
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text")
    hash_group.add_argument("-f", "--file")

    args = parser.parse_args()

    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    if args.command == "generate-keys":
        if args.algorithm == "rsa":
            from methods.asy import rsa; rsa.generate_keypair(args.priv, args.pub, args.bits)
        elif args.algorithm == "ecc":
            from methods.asy import ecc; ecc.generate_keypair(args.priv, args.pub)

    elif args.command == "encrypt":
        if args.disk:
            if not args.header or not args.password: sys.exit("[-] Disk encryption requires --header and -p")
            from methods.sym import aes_xts; from utils.disk import process_disk
            process_disk(args.disk, args.header, args.password, "encrypt", aes_xts, args.bits)
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes; 
                if args.text: print(aes.encrypt_text(args.text, args.password, args.bits))
                elif args.file: aes.encrypt_file(args.file, args.out, args.password, args.bits)
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20; 
                if args.text: print(chacha20.encrypt_text(args.text, args.password))
                elif args.file: chacha20.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "camellia":
                from methods.sym import camellia; 
                if args.text: print(camellia.encrypt_text(args.text, args.password, args.bits))
                elif args.file: camellia.encrypt_file(args.file, args.out, args.password, args.bits)
            elif args.algorithm == "rsa":
                from methods.asy import rsa; 
                if args.text: print(rsa.encrypt_text(args.text, args.pubkey))
                elif args.file: rsa.encrypt_file(args.file, args.out, args.pubkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                hybrid_engine.encrypt_file(args.file, args.out, args.pubkey, args.asy, args.sym)

    elif args.command == "decrypt":
        if args.disk:
            if not args.header or not args.password: sys.exit("[-] Disk decryption requires --header and -p")
            from methods.sym import aes_xts; from utils.disk import process_disk
            process_disk(args.disk, args.header, args.password, "decrypt", aes_xts)
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes; 
                if args.text: print(aes.decrypt_text(args.text, args.password))
                elif args.file: aes.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20; 
                if args.text: print(chacha20.decrypt_text(args.text, args.password))
                elif args.file: chacha20.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "camellia":
                from methods.sym import camellia; 
                if args.text: print(camellia.decrypt_text(args.text, args.password, args.bits))
                elif args.file: camellia.decrypt_file(args.file, args.out, args.password, args.bits)
            elif args.algorithm == "rsa":
                from methods.asy import rsa; 
                if args.text: print(rsa.decrypt_text(args.text, args.privkey))
                elif args.file: rsa.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)

    elif args.command in ["encode", "decode"]:
        check_file_output(args)
        if args.algorithm in ["base64", "b64"]:
            from methods.others import b64
            if args.command == "encode":
                if args.text: print(b64.encode_text(args.text))
                elif args.file: b64.encode_file(args.file, args.out)
            else:
                if args.text: print(b64.decode_text(args.text))
                elif args.file: b64.decode_file(args.file, args.out)
        elif args.algorithm == "hex":
            from methods.others import hexcode
            if args.command == "encode":
                if args.text: print(hexcode.encode_text(args.text))
                elif args.file: hexcode.encode_file(args.file, args.out)
            else:
                if args.text: print(hexcode.decode_text(args.text))
                elif args.file: hexcode.decode_file(args.file, args.out)

    elif args.command == "hash":
        if args.algorithm == "sha1": from methods.hash import sha1 as hash_module
        elif args.algorithm == "sha256": from methods.hash import sha256 as hash_module
        elif args.algorithm == "sha512": from methods.hash import sha512 as hash_module
        elif args.algorithm == "blake2b": from methods.hash import blake2b as hash_module
        elif args.algorithm == "blake2s": from methods.hash import blake2s as hash_module
            
        if args.text: print(hash_module.hash_text(args.text))
        elif args.file: print(hash_module.hash_file(args.file))

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()