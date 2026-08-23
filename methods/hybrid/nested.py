import os
import importlib

def encrypt_nested(filepath: str, out_path: str, password: str, algo1: str, algo2: str):
    temp_file = filepath + ".tmp"
    
    try:
        print(f"[*] Layer 1: Encrypting with {algo1.upper()}...")
        mod1 = importlib.import_module(f"methods.sym.{algo1}")
        mod1.encrypt_file(filepath, temp_file, password)
        
        print(f"[*] Layer 2: Encrypting with {algo2.upper()}...")
        mod2 = importlib.import_module(f"methods.sym.{algo2}")
        mod2.encrypt_file(temp_file, out_path, password)
        
        print(f"[+] Hybrid nested encryption completely successful: {out_path}")
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print("[*] Temporary trace files securely removed.")

def decrypt_nested(filepath: str, out_path: str, password: str, algo1: str, algo2: str):
    temp_file = filepath + ".tmp"
    
    try:
        print(f"[*] Layer 1: Decrypting outer layer ({algo2.upper()})...")
        mod2 = importlib.import_module(f"methods.sym.{algo2}")
        mod2.decrypt_file(filepath, temp_file, password)
        
        print(f"[*] Layer 2: Decrypting inner layer ({algo1.upper()})...")
        mod1 = importlib.import_module(f"methods.sym.{algo1}")
        mod1.decrypt_file(temp_file, out_path, password)
        
        print(f"[+] Hybrid nested decryption completely successful: {out_path}")
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print("[*] Temporary trace files securely removed.")