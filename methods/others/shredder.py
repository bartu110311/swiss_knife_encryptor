import os
import string
import random

def secure_delete(filepath: str, passes: int = 3):
    """
    Overwrites a file with random data multiple times before deleting it,
    preventing data recovery via forensic tools.
    """
    if not os.path.exists(filepath):
        print(f"[-] ERROR: Target file not found: {filepath}")
        return

    try:
        file_length = os.path.getsize(filepath)
        
        print(f"[*] Shredding initiated. File size: {file_length} bytes. Passes: {passes}")
        
        # Overwrite the file content with random bytes
        with open(filepath, "ba+", buffering=0) as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(file_length))
                print(f"    -> Pass {i+1}/{passes} completed.")
        
        # Rename the file to a random string to wipe the original filename from the file table
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        directory = os.path.dirname(filepath)
        new_filepath = os.path.join(directory, random_name + ".wiped")
        
        os.rename(filepath, new_filepath)
        os.remove(new_filepath)
        
        print(f"[+] TARGET DESTROYED: File has been securely wiped and deleted.")
        
    except Exception as e:
        print(f"[-] DANGER: Failed to securely wipe the file. Details: {e}")