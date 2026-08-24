import argparse
import sys

__version__ = "0.7.4"

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
    encrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "aes-gcm", "chacha20", "camellia", "sm4", "seed", "3des", "blowfish", "cast5", "fernet", "rsa", "hybrid"])
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
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20", "sm4", "seed", "3des", "blowfish", "cast5", "fernet", "aes-gcm"])

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", choices=["aes", "aes-xts", "aes-gcm", "chacha20", "camellia", "sm4", "seed", "3des", "blowfish", "cast5", "fernet", "rsa", "hybrid"])
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

    # --- SHREDDER & OTHERS... ---
    shred_parser = subparsers.add_parser("shred", help="Securely wipe and delete a file")
    shred_parser.add_argument("-f", "--file", required=True)
    shred_parser.add_argument("--passes", type=int, default=3)

    stego_parser = subparsers.add_parser("stego", help="Hide or extract text inside an image")
    stego_parser.add_argument("action", choices=["hide", "extract"])
    stego_parser.add_argument("-i", "--image", required=True)
    stego_parser.add_argument("-t", "--text")
    stego_parser.add_argument("-o", "--out")

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

    hash_parser = subparsers.add_parser("hash")
    hash_parser.add_argument("algorithm", choices=["sha1", "sha256", "sha512", "blake2b", "blake2s"])
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text")
    hash_group.add_argument("-f", "--file")

    hmac_parser = subparsers.add_parser("hmac")
    hmac_parser.add_argument("action", choices=["generate", "verify"])
    hmac_group = hmac_parser.add_mutually_exclusive_group(required=True)
    hmac_group.add_argument("-t", "--text")
    hmac_group.add_argument("-f", "--file")
    hmac_parser.add_argument("-k", "--key", required=True)
    hmac_parser.add_argument("--mac")

    args = parser.parse_args()

    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    if args.command == "generate-keys":
        if args.algorithm == "rsa": from methods.asy import rsa; rsa.generate_keypair(args.priv, args.pub, args.bits)
        elif args.algorithm == "ecc": from methods.asy import ecc; ecc.generate_keypair(args.priv, args.pub)

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
            elif args.algorithm == "aes-gcm":
                from methods.sym import aes_gcm; 
                if args.text: print(aes_gcm.encrypt_text(args.text, args.password, args.bits))
                elif args.file: aes_gcm.encrypt_file(args.file, args.out, args.password, args.bits)
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
            elif args.algorithm == "3des":
                from methods.sym import triple_des;
                if args.text: print(triple_des.encrypt_text(args.text, args.password))
                elif args.file: triple_des.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "blowfish":
                from methods.sym import blowfish_cipher;
                if args.text: print(blowfish_cipher.encrypt_text(args.text, args.password))
                elif args.file: blowfish_cipher.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "cast5":
                from methods.sym import cast5_cipher;
                if args.text: print(cast5_cipher.encrypt_text(args.text, args.password))
                elif args.file: cast5_cipher.encrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "fernet":
                from methods.sym import fernet_cipher;
                if args.text: print(fernet_cipher.encrypt_text(args.text, args.password))
                elif args.file: fernet_cipher.encrypt_file(args.file, args.out, args.password)
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
            elif args.algorithm == "aes-gcm":
                from methods.sym import aes_gcm; 
                if args.text: print(aes_gcm.decrypt_text(args.text, args.password))
                elif args.file: aes_gcm.decrypt_file(args.file, args.out, args.password)
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
            elif args.algorithm == "3des":
                from methods.sym import triple_des;
                if args.text: print(triple_des.decrypt_text(args.text, args.password))
                elif args.file: triple_des.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "blowfish":
                from methods.sym import blowfish_cipher;
                if args.text: print(blowfish_cipher.decrypt_text(args.text, args.password))
                elif args.file: blowfish_cipher.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "cast5":
                from methods.sym import cast5_cipher;
                if args.text: print(cast5_cipher.decrypt_text(args.text, args.password))
                elif args.file: cast5_cipher.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "fernet":
                from methods.sym import fernet_cipher;
                if args.text: print(fernet_cipher.decrypt_text(args.text, args.password))
                elif args.file: fernet_cipher.decrypt_file(args.file, args.out, args.password)
            elif args.algorithm == "rsa":
                from methods.asy import rsa; 
                if args.text: print(rsa.decrypt_text(args.text, args.privkey))
                elif args.file: rsa.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)

    elif args.command == "sign":
        if args.algorithm == "rsa": from methods.asy import rsa; rsa.sign_file(args.file, args.sig, args.privkey)
        elif args.algorithm == "ecc": from methods.asy import ecc; ecc.sign_file(args.file, args.sig, args.privkey)

    elif args.command == "verify":
        if args.algorithm == "rsa": from methods.asy import rsa; rsa.verify_file(args.file, args.sig, args.pubkey)
        elif args.algorithm == "ecc": from methods.asy import ecc; ecc.verify_file(args.file, args.sig, args.pubkey)

    elif args.command == "nested":
        from methods.hybrid import nested
        if args.action == "encrypt": nested.encrypt_nested(args.file, args.out, args.password, args.layer1, args.layer2)
        elif args.action == "decrypt": nested.decrypt_nested(args.file, args.out, args.password, args.layer1, args.layer2)

    elif args.command == "shred":
        from methods.others import shredder; shredder.secure_delete(args.file, args.passes)
        
    elif args.command == "stego":
        from methods.others import stego
        if args.action == "hide":
            if not args.text or not args.out: sys.exit("[-] Error: --text and --out required.")
            stego.hide_text(args.image, args.text, args.out)
        elif args.action == "extract": stego.extract_text(args.image)

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
        
    elif args.command == "hmac":
        from methods.hash import hmac_auth
        if args.action == "generate":
            if args.text: print(f"[+] HMAC-SHA256: {hmac_auth.generate_hmac_text(args.text, args.key)}")
            elif args.file: print(f"[+] HMAC-SHA256: {hmac_auth.generate_hmac_file(args.file, args.key)}")
        elif args.action == "verify":
            if not args.mac: sys.exit("[-] Error: --mac is required when verifying HMAC.")
            is_valid = False
            if args.text: is_valid = hmac_auth.verify_hmac_text(args.text, args.key, args.mac)
            elif args.file: is_valid = hmac_auth.verify_hmac_file(args.file, args.key, args.mac)
            
            if is_valid: print("[+] SUCCESS: HMAC signature is VALID and authentic.")
            else: print("[-] WARNING: HMAC signature is INVALID! Data may have been tampered with.")

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[-] CRITICAL ERROR: An unexpected issue occurred.\n    Details: {e}")
        sys.exit(1)