import argparse
import sys

__version__ = "0.7.0"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one cryptosystem with Digital Signatures.")
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
    encrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "camellia", "sm4", "rsa", "hybrid", "seed"])
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text")
    enc_group.add_argument("-f", "--file")
    enc_group.add_argument("-d", "--disk")
    
    encrypt_parser.add_argument("-o", "--out")
    encrypt_parser.add_argument("--header")
    encrypt_parser.add_argument("-p", "--password")
    encrypt_parser.add_argument("--pubkey")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256)
    encrypt_parser.add_argument("--asy", choices=["rsa", "ecc"])
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20", "sm4", "seed"])

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "chacha20", "camellia", "sm4", "rsa", "hybrid", "seed"])
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text")
    dec_group.add_argument("-f", "--file")
    dec_group.add_argument("-d", "--disk")
    
    decrypt_parser.add_argument("-o", "--out")
    decrypt_parser.add_argument("--header")
    decrypt_parser.add_argument("-p", "--password")
    decrypt_parser.add_argument("--privkey")
    decrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256)

    # --- SIGN ---
    sign_parser = subparsers.add_parser("sign", help="Sign a file with a private key")
    sign_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Asymmetric algorithm used for signing")
    sign_parser.add_argument("-f", "--file", required=True, help="File to sign")
    sign_parser.add_argument("--sig", required=True, help="Output path for the detached signature file (.sig)")
    sign_parser.add_argument("--privkey", required=True, help="Path to your private key")

    # --- VERIFY ---
    verify_parser = subparsers.add_parser("verify", help="Verify a detached signature of a file")
    verify_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Asymmetric algorithm used for verification")
    verify_parser.add_argument("-f", "--file", required=True, help="The original file")
    verify_parser.add_argument("--sig", required=True, help="The detached signature file (.sig)")
    verify_parser.add_argument("--pubkey", required=True, help="Path to the sender's public key")

    # --- NESTED ENCRYPTION ---
    nested_parser = subparsers.add_parser("nested", help="Apply double-layer nested encryption")
    nested_parser.add_argument("action", choices=["encrypt", "decrypt"])
    nested_parser.add_argument("--layer1", required=True, help="Inner layer algorithm (e.g., aes)")
    nested_parser.add_argument("--layer2", required=True, help="Outer layer algorithm (e.g., seed)")
    nested_parser.add_argument("-f", "--file", required=True)
    nested_parser.add_argument("-o", "--out", required=True)
    nested_parser.add_argument("-p", "--password", required=True)

    # --- SHREDDER (SECURE WIPE) ---
    shred_parser = subparsers.add_parser("shred", help="Securely wipe and delete a file")
    shred_parser.add_argument("-f", "--file", required=True, help="File to permanently delete")
    shred_parser.add_argument("--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")

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
            if not args.header or not args.password: sys.exit("[-] Error: Disk operations require --header and -p")
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
            elif args.algorithm == "sm4":
                from methods.sym import sm4;
                if args.text: print(sm4.encrypt_text(args.text, args.password))
                elif args.file: sm4.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "seed":
                from methods.sym import seed;
                if args.text: print(seed.encrypt_text(args.text, args.password))
                elif args.file: seed.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "rsa":
                from methods.asy import rsa; 
                if args.text: print(rsa.encrypt_text(args.text, args.pubkey))
                elif args.file: rsa.encrypt_file(args.file, args.out, args.pubkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                hybrid_engine.encrypt_file(args.file, args.out, args.pubkey, args.asy, args.sym)

    elif args.command == "decrypt":
        if args.disk:
            if not args.header or not args.password: sys.exit("[-] Error: Disk operations require --header and -p")
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
            elif args.algorithm == "sm4":
                from methods.sym import sm4;
                if args.text: print(sm4.decrypt_text(args.text, args.password))
                elif args.file: sm4.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "seed":
                from methods.sym import seed;
                if args.text: print(seed.decrypt_text(args.text, args.password))
                elif args.file: seed.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "rsa":
                from methods.asy import rsa; 
                if args.text: print(rsa.decrypt_text(args.text, args.privkey))
                elif args.file: rsa.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)

    elif args.command == "sign":
        if args.algorithm == "rsa":
            from methods.asy import rsa
            rsa.sign_file(args.file, args.sig, args.privkey)
        elif args.algorithm == "ecc":
            from methods.asy import ecc
            ecc.sign_file(args.file, args.sig, args.privkey)

    elif args.command == "verify":
        if args.algorithm == "rsa":
            from methods.asy import rsa
            rsa.verify_file(args.file, args.sig, args.pubkey)
        elif args.algorithm == "ecc":
            from methods.asy import ecc
            ecc.verify_file(args.file, args.sig, args.pubkey)

    elif args.command == "nested":
        from methods.hybrid import nested
        if args.action == "encrypt":
            nested.encrypt_nested(args.file, args.out, args.password, args.layer1, args.layer2)
        elif args.action == "decrypt":
            nested.decrypt_nested(args.file, args.out, args.password, args.layer1, args.layer2)

    elif args.command == "shred":
        from methods.others import shredder
        shredder.secure_delete(args.file, args.passes)

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
    try:
        main()
    except FileNotFoundError as e:
        print(f"[-] ERROR: File not found. Please verify the file paths.\n    Details: {e}")
        sys.exit(1)
    except PermissionError:
        print("[-] ERROR: Permission denied. You don't have rights to read/write this file.")
        sys.exit(1)
    except ValueError as e:
        print(f"[-] ERROR: Invalid value or corrupted data.\n    Details: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] WARNING: Operation cancelled by user (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        print(f"[-] CRITICAL ERROR: An unexpected issue occurred.\n    Details: {e}")
        sys.exit(1)