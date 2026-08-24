import argparse
import sys

__version__ = "0.7.6"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one cryptosystem with Digital Signatures.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    crypto_choices = [
        "aes", "aes-xts", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb",
        "chacha20", "camellia", "sm4", "seed", "3des", "blowfish",
        "cast5", "fernet", "rsa", "hybrid"
    ]

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Asymmetric algorithm")
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (for RSA)")

    # --- ENCRYPT ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text, files, or disks")
    encrypt_parser.add_argument("algorithm", choices=crypto_choices, help="Encryption algorithm")
    enc_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    enc_group.add_argument("-t", "--text", help="Text to encrypt")
    enc_group.add_argument("-f", "--file", help="File to encrypt")
    enc_group.add_argument("-d", "--disk", help="Disk partition to encrypt")
    
    encrypt_parser.add_argument("-o", "--out", help="Output file path")
    encrypt_parser.add_argument("--header", help="Header file path for disk encryption")
    encrypt_parser.add_argument("-p", "--password", help="Passphrase for encryption")
    encrypt_parser.add_argument("--pubkey", help="Public key path for asymmetric/hybrid encryption")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits")
    encrypt_parser.add_argument("--asy", choices=["rsa", "ecc"], help="Asymmetric mode for hybrid scheme")
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20", "sm4", "seed", "3des", "blowfish", "cast5", "fernet", "aes-gcm"], help="Symmetric mode for hybrid scheme")

    # --- DECRYPT ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text, files, or disks")
    decrypt_parser.add_argument("algorithm", choices=crypto_choices, help="Decryption algorithm")
    dec_group = decrypt_parser.add_mutually_exclusive_group(required=True)
    dec_group.add_argument("-t", "--text", help="Text to decrypt")
    dec_group.add_argument("-f", "--file", help="File to decrypt")
    dec_group.add_argument("-d", "--disk", help="Disk partition to decrypt")
    
    decrypt_parser.add_argument("-o", "--out", help="Output file path")
    decrypt_parser.add_argument("--header", help="Header file path for disk decryption")
    decrypt_parser.add_argument("-p", "--password", help="Passphrase for decryption")
    decrypt_parser.add_argument("--privkey", help="Private key path for asymmetric/hybrid decryption")
    decrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits")

    # --- SIGN ---
    sign_parser = subparsers.add_parser("sign", help="Sign a file with a private key")
    sign_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Asymmetric algorithm used for signing")
    sign_parser.add_argument("-f", "--file", required=True, help="File to sign")
    sign_parser.add_argument("--sig", required=True, help="Output path for detached signature file (.sig)")
    sign_parser.add_argument("--privkey", required=True, help="Path to your private key")

    # --- VERIFY ---
    verify_parser = subparsers.add_parser("verify", help="Verify a detached signature of a file")
    verify_parser.add_argument("algorithm", choices=["rsa", "ecc"], help="Asymmetric algorithm used for verification")
    verify_parser.add_argument("-f", "--file", required=True, help="The original file")
    verify_parser.add_argument("--sig", required=True, help="The detached signature file (.sig)")
    verify_parser.add_argument("--pubkey", required=True, help="Path to sender's public key")

    # --- NESTED ENCRYPTION ---
    nested_parser = subparsers.add_parser("nested", help="Apply double-layer nested encryption")
    nested_parser.add_argument("action", choices=["encrypt", "decrypt"], help="Nested operation type")
    nested_parser.add_argument("--layer1", required=True, help="Inner layer algorithm")
    nested_parser.add_argument("--layer2", required=True, help="Outer layer algorithm")
    nested_parser.add_argument("-f", "--file", required=True, help="Target file")
    nested_parser.add_argument("-o", "--out", required=True, help="Output file path")
    nested_parser.add_argument("-p", "--password", required=True, help="Passphrase")

    # --- SHREDDER ---
    shred_parser = subparsers.add_parser("shred", help="Securely wipe and delete a file")
    shred_parser.add_argument("-f", "--file", required=True, help="File to shred")
    shred_parser.add_argument("--passes", type=int, default=3, help="Number of overwrite passes")

    # --- STEGANOGRAPHY ---
    stego_parser = subparsers.add_parser("stego", help="Hide or extract text inside an image")
    stego_parser.add_argument("action", choices=["hide", "extract"], help="Steganography operation")
    stego_parser.add_argument("-i", "--image", required=True, help="Image file path")
    stego_parser.add_argument("-t", "--text", help="Text to hide")
    stego_parser.add_argument("-o", "--out", help="Output image file path")

    # --- ENCODE / DECODE ---
    encode_parser = subparsers.add_parser("encode", help="Encode text or file into Base64 or Hex")
    encode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    encd_grp = encode_parser.add_mutually_exclusive_group(required=True)
    encd_grp.add_argument("-t", "--text", help="Text to encode")
    encd_grp.add_argument("-f", "--file", help="File to encode")
    encode_parser.add_argument("-o", "--out", help="Output file path")

    decode_parser = subparsers.add_parser("decode", help="Decode Base64 or Hex string/file")
    decode_parser.add_argument("algorithm", choices=["base64", "b64", "hex"])
    decd_grp = decode_parser.add_mutually_exclusive_group(required=True)
    decd_grp.add_argument("-t", "--text", help="Text to decode")
    decd_grp.add_argument("-f", "--file", help="File to decode")
    decode_parser.add_argument("-o", "--out", help="Output file path")

    # --- HASH ---
    hash_parser = subparsers.add_parser("hash", help="Calculate or verify cryptographic hashes")
    hash_parser.add_argument("algorithm", choices=["sha1", "sha256", "sha512", "blake2b", "blake2s", "argon2"])
    hash_parser.add_argument("--verify", help="Argon2 hash string to verify given plain text against")
    hash_group = hash_parser.add_mutually_exclusive_group(required=True)
    hash_group.add_argument("-t", "--text", help="Text to hash")
    hash_group.add_argument("-f", "--file", help="File to hash")

    # --- HMAC ---
    hmac_parser = subparsers.add_parser("hmac", help="Generate or verify HMAC signatures")
    hmac_parser.add_argument("action", choices=["generate", "verify"])
    hmac_group = hmac_parser.add_mutually_exclusive_group(required=True)
    hmac_group.add_argument("-t", "--text", help="Text data")
    hmac_group.add_argument("-f", "--file", help="File data")
    hmac_parser.add_argument("-k", "--key", required=True, help="Secret HMAC key")
    hmac_parser.add_argument("--mac", help="MAC string to verify against")

    args = parser.parse_args()

    def check_file_output(args):
        if args.file and not args.out:
            sys.exit("[-] Error: Output path (-o or --out) is required when processing a file.")

    if args.command == "generate-keys":
        if args.algorithm == "rsa":
            from methods.asy import rsa
            rsa.generate_keypair(args.priv, args.pub, args.bits)
        elif args.algorithm == "ecc":
            from methods.asy import ecc
            ecc.generate_keypair(args.priv, args.pub)

    elif args.command == "encrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Error: Disk operations require --header and -p")
            from methods.sym import aes_xts
            from utils.disk import process_disk
            process_disk(args.disk, args.header, args.password, "encrypt", aes_xts, args.bits)
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes as module
            elif args.algorithm == "aes-gcm":
                from methods.sym import aes_gcm as module
            elif args.algorithm == "aes-ctr":
                from methods.sym import aes_ctr as module
            elif args.algorithm == "aes-cfb":
                from methods.sym import aes_cfb as module
            elif args.algorithm == "aes-ofb":
                from methods.sym import aes_ofb as module
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20 as module
            elif args.algorithm == "camellia":
                from methods.sym import camellia as module
            elif args.algorithm == "sm4":
                from methods.sym import sm4 as module
            elif args.algorithm == "seed":
                from methods.sym import seed as module
            elif args.algorithm == "3des":
                from methods.sym import triple_des as module
            elif args.algorithm == "blowfish":
                from methods.sym import blowfish_cipher as module
            elif args.algorithm == "cast5":
                from methods.sym import cast5_cipher as module
            elif args.algorithm == "fernet":
                from methods.sym import fernet_cipher as module
            elif args.algorithm == "rsa":
                from methods.asy import rsa as module
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine

            if args.algorithm == "rsa":
                if args.text: print(module.encrypt_text(args.text, args.pubkey))
                elif args.file: module.encrypt_file(args.file, args.out, args.pubkey)
            elif args.algorithm == "hybrid":
                hybrid_engine.encrypt_file(args.file, args.out, args.pubkey, args.asy, args.sym)
            elif args.algorithm in ["aes", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb", "camellia"]:
                if args.text: print(module.encrypt_text(args.text, args.password, args.bits))
                elif args.file: module.encrypt_file(args.file, args.out, args.password, args.bits)
            else:
                if args.text: print(module.encrypt_text(args.text, args.password))
                elif args.file: module.encrypt_file(args.file, args.out, args.password)

    elif args.command == "decrypt":
        if args.disk:
            if not args.header or not args.password:
                sys.exit("[-] Error: Disk operations require --header and -p")
            from methods.sym import aes_xts
            from utils.disk import process_disk
            process_disk(args.disk, args.header, args.password, "decrypt", aes_xts)
        else:
            check_file_output(args)
            if args.algorithm == "aes":
                from methods.sym import aes as module
            elif args.algorithm == "aes-gcm":
                from methods.sym import aes_gcm as module
            elif args.algorithm == "aes-ctr":
                from methods.sym import aes_ctr as module
            elif args.algorithm == "aes-cfb":
                from methods.sym import aes_cfb as module
            elif args.algorithm == "aes-ofb":
                from methods.sym import aes_ofb as module
            elif args.algorithm == "chacha20":
                from methods.sym import chacha20 as module
            elif args.algorithm == "camellia":
                from methods.sym import camellia as module
            elif args.algorithm == "sm4":
                from methods.sym import sm4 as module
            elif args.algorithm == "seed":
                from methods.sym import seed as module
            elif args.algorithm == "3des":
                from methods.sym import triple_des as module
            elif args.algorithm == "blowfish":
                from methods.sym import blowfish_cipher as module
            elif args.algorithm == "cast5":
                from methods.sym import cast5_cipher as module
            elif args.algorithm == "fernet":
                from methods.sym import fernet_cipher as module
            elif args.algorithm == "rsa":
                from methods.asy import rsa as module
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine

            if args.algorithm == "rsa":
                if args.text: print(module.decrypt_text(args.text, args.privkey))
                elif args.file: module.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm in ["aes", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb", "camellia"]:
                if args.text: print(module.decrypt_text(args.text, args.password, args.bits))
                elif args.file: module.decrypt_file(args.file, args.out, args.password, args.bits)
            else:
                if args.text: print(module.decrypt_text(args.text, args.password))
                elif args.file: module.decrypt_file(args.file, args.out, args.password)

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

    elif args.command == "stego":
        from methods.others import stego
        if args.action == "hide":
            if not args.text or not args.out:
                sys.exit("[-] Error: --text and --out parameters are required for hiding text.")
            stego.hide_text(args.image, args.text, args.out)
        elif args.action == "extract":
            stego.extract_text(args.image)

    elif args.command in ["encode", "decode"]:
        check_file_output(args)
        if args.algorithm in ["base64", "b64"]:
            from methods.others import b64 as module
        elif args.algorithm == "hex":
            from methods.others import hexcode as module

        if args.command == "encode":
            if args.text: print(module.encode_text(args.text))
            elif args.file: module.encode_file(args.file, args.out)
        else:
            if args.text: print(module.decode_text(args.text))
            elif args.file: module.decode_file(args.file, args.out)

    elif args.command == "hash":
        if args.algorithm == "argon2":
            from methods.hash import argon2
            if args.verify:
                if not args.text:
                    sys.exit("[-] Error: Argon2 verify requires a plain text (-t) to check against the hash.")
                is_valid = argon2.verify_text(args.text, args.verify)
                if is_valid:
                    print("[+] SUCCESS: Argon2 Password Match!")
                else:
                    print("[-] ERROR: Invalid password!")
            else:
                if args.text:
                    print(argon2.hash_text(args.text))
                elif args.file:
                    sys.exit("[-] Error: Argon2 is typically used for password hashing (text), not files.")
        else:
            if args.algorithm == "sha1":
                from methods.hash import sha1 as hash_module
            elif args.algorithm == "sha256":
                from methods.hash import sha256 as hash_module
            elif args.algorithm == "sha512":
                from methods.hash import sha512 as hash_module
            elif args.algorithm == "blake2b":
                from methods.hash import blake2b as hash_module
            elif args.algorithm == "blake2s":
                from methods.hash import blake2s as hash_module

            if args.text:
                print(hash_module.hash_text(args.text))
            elif args.file:
                print(hash_module.hash_file(args.file))

    elif args.command == "hmac":
        from methods.hash import hmac_auth
        if args.action == "generate":
            if args.text:
                print(f"[+] HMAC-SHA256: {hmac_auth.generate_hmac_text(args.text, args.key)}")
            elif args.file:
                print(f"[+] HMAC-SHA256: {hmac_auth.generate_hmac_file(args.file, args.key)}")
        elif args.action == "verify":
            if not args.mac:
                sys.exit("[-] Error: --mac is required when verifying HMAC.")
            is_valid = False
            if args.text:
                is_valid = hmac_auth.verify_hmac_text(args.text, args.key, args.mac)
            elif args.file:
                is_valid = hmac_auth.verify_hmac_file(args.file, args.key, args.mac)

            if is_valid:
                print("[+] SUCCESS: HMAC signature is VALID and authentic.")
            else:
                print("[-] WARNING: HMAC signature is INVALID! Data may have been tampered with.")

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[-] CRITICAL ERROR: An unexpected issue occurred.\n    Details: {e}")
        sys.exit(1)