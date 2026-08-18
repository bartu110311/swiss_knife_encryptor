import os
import sys

def process_disk(disk_path: str, header_path: str, password: str, mode: str, algo_module, bits: int = 256):
    """Ayrık Başlıklı (Detached Header) In-Place Disk/Sektör İşleme Motoru"""
    chunk_size = 4096  # Fiziksel disk sektörleri genelde 4KB (4096 byte) okunur
    
    if mode == "encrypt":
        salt = os.urandom(16)
        with open(header_path, "wb") as h:
            h.write(salt)
        print(f"[*] Detached Header (Salt) saved to '{header_path}'. KEEP THIS SAFE!")
    else:
        if not os.path.exists(header_path):
            sys.exit(f"[-] Error: Detached header file '{header_path}' not found!")
        with open(header_path, "rb") as h:
            salt = h.read(16)
            
    key = algo_module._derive_key(password, salt, bits)
    
    print(f"\n[!!!] DANGER - READ CAREFULLY [!!!]")
    print(f"This will OVERWRITE '{disk_path}' IN-PLACE.")
    print("If you lose the password or the header file, data is gone forever.")
    confirm = input("Type 'YES' (all caps) to continue: ")
    if confirm != "YES":
        sys.exit("[-] Operation aborted by user.")
        
    print(f"[*] Starting in-place {mode}ion on {disk_path}...")
    try:
        with open(disk_path, "r+b") as f:
            chunk_idx = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                
                # XTS algoritması 16 bytelık blokların katlarını ister.
                # Diskin sonunda tam blok kalmazsa null-byte ile tamamlıyoruz.
                if len(chunk) % 16 != 0:
                    chunk = chunk.ljust(len(chunk) + (16 - len(chunk) % 16), b'\0')

                # İmleci okuduğumuz verinin başına geri alıp üstüne yazıyoruz
                f.seek(-len(chunk), 1)  
                
                processed = algo_module._process_chunk(chunk, key, chunk_idx, encrypt=(mode=="encrypt"))
                f.write(processed)
                
                chunk_idx += 1
        print(f"[+] {mode.capitalize()}ion completed successfully!")
    except PermissionError:
        sys.exit("[-] Permission Denied! Disk operations require Administrator/Root (sudo) privileges.")
    except Exception as e:
        sys.exit(f"[-] Fatal error during disk operation: {e}")