import argparse
import sys

__version__ = "0.9.0-beta2"

def main():
    parser = argparse.ArgumentParser(description="Swiss Knife Encryptor - All-in-one cryptosystem toolkit.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s v{__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available operations")

    crypto_choices = [
        "aes", "aes-xts", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb",
        "chacha20", "xchacha20", "camellia", "sm4", "seed", "3des", "blowfish",
        "cast5", "fernet", "rc4", "twofish", "kuznyechik", "aria", "rsa", "paillier", "hybrid",
        "kyber", "ml-kem"
    ]

    pqc_sig_choices = ["dilithium", "ml-dsa", "falcon", "sphincs", "slh-dsa"]
    all_sig_choices = ["rsa", "ecc", "ed25519"] + pqc_sig_choices

    # --- GENERATE KEYS ---
    keys_parser = subparsers.add_parser("generate-keys", help="Generate public/private key pairs")
    keys_parser.add_argument(
        "algorithm", 
        choices=["rsa", "ecc", "ed25519", "ecdh", "paillier", "schnorr", "kyber", "ml-kem", "dilithium", "ml-dsa", "falcon", "sphincs", "slh-dsa"], 
        help="Asymmetric, ZKP, or Post-Quantum (PQC) algorithm"
    )
    keys_parser.add_argument("--pub", default="public.key", help="Path to save public key")
    keys_parser.add_argument("--priv", default="private.key", help="Path to save private key")
    keys_parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (for RSA/Paillier)")

    # --- ECDH KEY EXCHANGE ---
    ecdh_parser = subparsers.add_parser("ecdh", help="Derive shared secret via Elliptic Curve Diffie-Hellman")
    ecdh_parser.add_argument("--privkey", required=True, help="Path to your ECDH private key")
    ecdh_parser.add_argument("--peerkey", required=True, help="Path to peer's ECDH public key")

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
    encrypt_parser.add_argument("--pubkey", help="Public key path for asymmetric/hybrid/PQC encryption")
    encrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits")
    encrypt_parser.add_argument("--asy", choices=["rsa", "ecc", "kyber"], help="Asymmetric mode for hybrid scheme")
    encrypt_parser.add_argument("--sym", choices=["aes", "chacha20", "sm4", "seed", "3des", "blowfish", "cast5", "fernet", "aes-gcm", "aria"], help="Symmetric mode for hybrid scheme")

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
    decrypt_parser.add_argument("--privkey", help="Private key path for asymmetric/hybrid/PQC decryption")
    decrypt_parser.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="Key size in bits")

    # --- SIGN ---
    sign_parser = subparsers.add_parser("sign", help="Sign a file with a private key (Classical & PQC)")
    sign_parser.add_argument("algorithm", choices=all_sig_choices, help="Algorithm used for signing")
    sign_parser.add_argument("-f", "--file", required=True, help="File to sign")
    sign_parser.add_argument("--sig", required=True, help="Output path for detached signature file (.sig)")
    sign_parser.add_argument("--privkey", required=True, help="Path to your private key")

    # --- VERIFY ---
    verify_parser = subparsers.add_parser("verify", help="Verify a detached signature of a file (Classical & PQC)")
    verify_parser.add_argument("algorithm", choices=all_sig_choices, help="Algorithm used for verification")
    verify_parser.add_argument("-f", "--file", required=True, help="The original file")
    verify_parser.add_argument("--sig", required=True, help="The detached signature file (.sig)")
    verify_parser.add_argument("--pubkey", required=True, help="Path to sender's public key")

    # --- ZERO-KNOWLEDGE PROOF (SCHNORR ZKP) ---
    zkp_parser = subparsers.add_parser("zkp", help="Schnorr Zero-Knowledge Proof operations")
    zkp_parser.add_argument("action", choices=["prove", "verify"], help="ZKP Action")
    zkp_parser.add_argument("--privkey", help="Private key file for proving")
    zkp_parser.add_argument("--pubkey", help="Public key file for verification")
    zkp_parser.add_argument("--proof", help="Proof JSON string or path to proof file")
    zkp_parser.add_argument("-m", "--msg", default="", help="Optional context message for ZKP")

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

    # --- STEGANOGRAPHY (IMAGE & AUDIO) ---
    stego_parser = subparsers.add_parser("stego", help="Hide or extract text inside an image or audio file")
    stego_parser.add_argument("action", choices=["hide", "extract"], help="Steganography operation")
    stego_parser.add_argument("-m", "--medium", choices=["image", "audio"], default="image", help="Medium type: image (default) or audio")
    stego_parser.add_argument("-i", "--image", help="Image file path")
    stego_parser.add_argument("-a", "--audio", help="Audio file path (WAV)")
    stego_parser.add_argument("-t", "--text", help="Text to hide")
    stego_parser.add_argument("-o", "--out", help="Output file path")

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
    hash_parser.add_argument("algorithm", choices=["md5", "sha1", "sha256", "sha512", "blake2b", "blake2s", "argon2", "bcrypt", "pbkdf2", "scrypt", "sha3_256", "sha3_512", "ripemd160"])
    hash_parser.add_argument("--verify", help="Hash string to verify given plain text against (for Argon2 / Bcrypt)")
    hash_parser.add_argument("--salt", help="Salt in hex format for PBKDF2 / Scrypt")
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
        elif args.algorithm == "ed25519":
            from methods.asy import ed25519_sign
            ed25519_sign.generate_keypair(args.priv, args.pub)
        elif args.algorithm == "ecdh":
            from methods.asy import ecdh
            ecdh.generate_keypair(args.priv, args.pub)
        elif args.algorithm == "paillier":
            from methods.asy import paillier
            paillier.generate_keypair(args.priv, args.pub, args.bits)
        elif args.algorithm == "schnorr":
            from methods.others import schnorr_zkp
            schnorr_zkp.generate_keypair(args.priv, args.pub)
        # --- PQC Key Generation ---
        elif args.algorithm in ["kyber", "ml-kem"]:
            from methods.asy.pqc import kyber
            kyber.generate_keypair(args.priv, args.pub)
        elif args.algorithm in ["dilithium", "ml-dsa"]:
            from methods.asy.pqc import dilithium
            dilithium.generate_keypair(args.priv, args.pub)
        elif args.algorithm == "falcon":
            from methods.asy.pqc import falcon
            falcon.generate_keypair(args.priv, args.pub)
        elif args.algorithm in ["sphincs", "slh-dsa"]:
            from methods.asy.pqc import sphincs
            sphincs.generate_keypair(args.priv, args.pub)

    elif args.command == "ecdh":
        from methods.asy import ecdh
        shared_secret = ecdh.derive_shared_secret(args.privkey, args.peerkey)
        print(f"[+] Derived ECDH Shared Secret: {shared_secret}")

    elif args.command == "zkp":
        from methods.others import schnorr_zkp
        if args.action == "prove":
            if not args.privkey:
                sys.exit("[-] Error: --privkey path is required for generating proof.")
            proof = schnorr_zkp.generate_proof(args.privkey, args.msg)
            print(f"[+] Generated ZKP Proof:\n{proof}")
        elif args.action == "verify":
            if not args.pubkey or not args.proof:
                sys.exit("[-] Error: --pubkey and --proof parameters are required for verification.")
            is_valid = schnorr_zkp.verify_proof(args.pubkey, args.proof)
            if is_valid:
                print("[+] SUCCESS: ZKP Proof is VALID!")
            else:
                print("[-] ERROR: Invalid ZKP Proof!")

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
            elif args.algorithm == "xchacha20":
                from methods.sym import xchacha20 as module
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
            elif args.algorithm == "rc4":
                from methods.sym import rc4 as module
            elif args.algorithm == "twofish":
                from methods.sym import twofish_cipher as module
            elif args.algorithm == "kuznyechik":
                from methods.sym import kuznyechik as module
            elif args.algorithm == "aria":
                from methods.sym import aria as module
            elif args.algorithm == "rsa":
                from methods.asy import rsa as module
            elif args.algorithm == "paillier":
                from methods.asy import paillier as module
            elif args.algorithm in ["kyber", "ml-kem"]:
                from methods.asy.pqc import kyber as module
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine

            if args.algorithm in ["rsa", "paillier", "kyber", "ml-kem"]:
                if not args.pubkey:
                    sys.exit("[-] Error: --pubkey is required for asymmetric/PQC encryption.")
                if args.text: print(module.encrypt_text(args.text, args.pubkey))
                elif args.file: module.encrypt_file(args.file, args.out, args.pubkey)
            elif args.algorithm == "hybrid":
                hybrid_engine.encrypt_file(args.file, args.out, args.pubkey, args.asy, args.sym)
            elif args.algorithm in ["aes", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb", "camellia", "aria"]:
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
            elif args.algorithm == "xchacha20":
                from methods.sym import xchacha20 as module
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
            elif args.algorithm == "rc4":
                from methods.sym import rc4 as module
            elif args.algorithm == "twofish":
                from methods.sym import twofish_cipher as module
            elif args.algorithm == "kuznyechik":
                from methods.sym import kuznyechik as module
            elif args.algorithm == "aria":
                from methods.sym import aria as module
            elif args.algorithm == "rsa":
                from methods.asy import rsa as module
            elif args.algorithm == "paillier":
                from methods.asy import paillier as module
            elif args.algorithm in ["kyber", "ml-kem"]:
                from methods.asy.pqc import kyber as module
            elif args.algorithm == "hybrid":
                from methods.hybrid import engine as hybrid_engine

            if args.algorithm in ["rsa", "paillier", "kyber", "ml-kem"]:
                if not args.privkey:
                    sys.exit("[-] Error: --privkey is required for asymmetric/PQC decryption.")
                if args.text: print(module.decrypt_text(args.text, args.privkey))
                elif args.file: module.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm == "hybrid":
                hybrid_engine.decrypt_file(args.file, args.out, args.privkey)
            elif args.algorithm in ["aes", "aes-gcm", "aes-ctr", "aes-cfb", "aes-ofb", "camellia", "aria"]:
                if args.text: print(module.decrypt_text(args.text, args.password, args.bits))
                elif args.file: module.decrypt_file(args.file, args.out, args.password, args.bits)
            else:
                if args.text: print(module.decrypt_text(args.text, args.password))
                elif args.file: module.decrypt_file(args.file, args.out, args.password)

    elif args.command == "sign":
        if args.algorithm == "rsa":
            from methods.asy import rsa as sig_module
        elif args.algorithm == "ecc":
            from methods.asy import ecc as sig_module
        elif args.algorithm == "ed25519":
            from methods.asy import ed25519_sign as sig_module
        # --- PQC Signatures ---
        elif args.algorithm in ["dilithium", "ml-dsa"]:
            from methods.asy.pqc import dilithium as sig_module
        elif args.algorithm == "falcon":
            from methods.asy.pqc import falcon as sig_module
        elif args.algorithm in ["sphincs", "slh-dsa"]:
            from methods.asy.pqc import sphincs as sig_module

        sig_module.sign_file(args.file, args.sig, args.privkey)

    elif args.command == "verify":
        if args.algorithm == "rsa":
            from methods.asy import rsa as sig_module
        elif args.algorithm == "ecc":
            from methods.asy import ecc as sig_module
        elif args.algorithm == "ed25519":
            from methods.asy import ed25519_sign as sig_module
        # --- PQC Verification ---
        elif args.algorithm in ["dilithium", "ml-dsa"]:
            from methods.asy.pqc import dilithium as sig_module
        elif args.algorithm == "falcon":
            from methods.asy.pqc import falcon as sig_module
        elif args.algorithm in ["sphincs", "slh-dsa"]:
            from methods.asy.pqc import sphincs as sig_module

        sig_module.verify_file(args.file, args.sig, args.pubkey)

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
        if args.medium == "audio" or args.audio:
            from methods.others import audio_stego
            target_audio = args.audio or args.image
            if not target_audio:
                sys.exit("[-] Error: Audio file path (-a / --audio) is required for audio steganography.")
            
            if args.action == "hide":
                if not args.text or not args.out:
                    sys.exit("[-] Error: --text and --out parameters are required for hiding text in audio.")
                audio_stego.hide_text(target_audio, args.text, args.out)
            elif args.action == "extract":
                audio_stego.extract_text(target_audio)
        else:
            from methods.others import stego
            target_image = args.image or args.audio
            if not target_image:
                sys.exit("[-] Error: Image file path (-i / --image) is required for image steganography.")

            if args.action == "hide":
                if not args.text or not args.out:
                    sys.exit("[-] Error: --text and --out parameters are required for hiding text in image.")
                stego.hide_text(target_image, args.text, args.out)
            elif args.action == "extract":
                stego.extract_text(target_image)

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
                if is_valid: print("[+] SUCCESS: Argon2 Password Match!")
                else: print("[-] ERROR: Invalid password!")
            else:
                if args.text: print(argon2.hash_text(args.text))
        elif args.algorithm == "bcrypt":
            from methods.hash import bcrypt_hash
            if args.verify:
                if not args.text:
                    sys.exit("[-] Error: Bcrypt verify requires a plain text (-t) to check against the hash.")
                is_valid = bcrypt_hash.verify_text(args.text, args.verify)
                if is_valid: print("[+] SUCCESS: Bcrypt Password Match!")
                else: print("[-] ERROR: Invalid password!")
            else:
                if args.text: print(bcrypt_hash.hash_text(args.text))
        elif args.algorithm == "ripemd160":
            from methods.hash import ripemd160
            if args.text: print(ripemd160.hash_text(args.text))
            elif args.file: print(ripemd160.hash_file(args.file))
        elif args.algorithm == "pbkdf2":
            from methods.hash import pbkdf2
            if args.text: print(pbkdf2.hash_text(args.text, args.salt))
        elif args.algorithm == "scrypt":
            from methods.hash import scrypt
            if args.text: print(scrypt.hash_text(args.text, args.salt))
        elif args.algorithm in ["sha3_256", "sha3_512"]:
            from methods.hash import sha3
            variant = "256" if args.algorithm == "sha3_256" else "512"
            if args.text: print(sha3.hash_text(args.text, variant))
            elif args.file: print(sha3.hash_file(args.file, variant))
        elif args.algorithm == "md5":
            from methods.hash import md5
            if args.text: print(md5.hash_text(args.text))
            elif args.file: print(md5.hash_file(args.file))
        else:
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
            else: print("[-] WARNING: HMAC signature is INVALID!")

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[-] CRITICAL ERROR: {e}")
        sys.exit(1)