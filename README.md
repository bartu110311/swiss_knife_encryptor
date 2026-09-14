# swiss_knife_encryptor

All-in-one text/file/disk encryptor/decryptor/hash verifier with 45 algo, built on Python.

## Info

Cryptography methods are mentioned as *algo* in this Readme.<br>
For better explanation, I used emojis; but Readme itself written by a Human, not AI<br>
README ver 1.0.0_p2;<br>
main.py ver 0.9.0_beta2

## Features

- Encrypt / Decrypt / Encode / Decode / Sign / Verify / Hash with 45 different cryptography methods
- AES (CBC, GCM, CTR, CFB, OFB, XTS), ChaCha20 / XChaCha20, Camellia, SM4, SEED, 3DES, Blowfish, CAST5, Twofish, Fernet, RC4, Kuznyechik, ARIA, RSA, Paillier, EDHC, ECC / Ed25519, Schnorr ZKP, Argon2, Bcrypt, Blake2b, Blake2s, HMAC, MD5, PBKDF2, RIPEMD-160, Scrypt, SHA-1, SHA-256, SHA-512, SHA-3, Post-Quantum Cryptography, Base64, Hex
- Hybrid / Nested Encryption, File Shedder
- Picture Stenography and Audio Stenography
- Terminal based easy-to-use client
- Windows, Linux and MacOS supported

## Requirements

You need any operating system (Windows, Linux or MacOS) that have Python 3.8 or above installed. This project is built on Python 3.13 and some other cryptography libraries. We will guide you how you can install these libraries
- A CPU with AES or any cryptography instruction is recommended for faster calculations but any CPU will get the job done effortlessly. If you don't know do you have a CPU with these instructions, don't worry, it will work well even without it 😉
- In order to encrypt disks in Linux/ Unix; you may need sudo privileges in order for it to work properly
- cryptography, argon2-cffi, pillow, twofish and bcrypt libraries are required in order for the app to run properly.

## Installation

You need Python and some cryptography libraries in order this app to work. The installation of Python is shown here 👇

### Windows

1. Open PowerShell or Command Prompt.
2. Run the following command to install the version 3.13 of Python (or you can install the newest version with changing version number, refer to internet):
```bash
winget install Python.Python.3.13
```
3. Close the terminal and open a new one in order to refresh the system variables. If you write the following code and you see the version number, than you're good to go!
```bash
python --version
```
4. Install Git to clone this repo (or just install the zip and skip to 7th step):
```bash
winget install --id Git.Git -e --source winget
```
5. If succesful, you should see version number after you write this:
```bash
git --version
```
6. Clone this repository:
```bash
git clone https://github.com/bartu110311/swiss_knife_encryptor.git
```
7. If you installed the zip, open Powershell or Command Prompt **at the folder that contains the main.py file** else it won't work, if you cloned the repository, than use the already-open terminal. Use this code to install the libraries the program needs:
```bash
pip install -r requirements.txt
```

### Linux

1. Update your local package index (it may ask you for password):
```bash
sudo apt update
```
2. Install Python3 and pip:
```bash
sudo apt install python3 python3-pip
```
3. If succesful, you need to see the version number after you write:
```bash
python3 --version
```
4. Install Git to clone the repository:
```bash
sudo apt install git
```
5. If succesful, you need to see the version number after you write:
```bash
git --versiom
```
6. Clone this repository:
```bash
git clone https://github.com/bartu110311/swiss_knife_encryptor.git
```
7. Install the reqıired libraries:
```bash
pip install -r requirements.txt
```

### MacOS

1. Open Terminal. Run this code if homebrew isn't installed:
```bash
/bin/bash -c "$(curl -fsSL https://githubusercontent.com)"
```
2. Install Python via Homebrew:
```bash
brew install python
```
3. If succesful, you need to see the version number after you write:
```bash
python3 --version
```
4. Install Git via Homebrew:
```bash
brew install git
```
5. If succesful, you need to see the version number after you write:
```bash
git --version
```
6. Clone this repository:
```bash
git clone https://github.com/bartu110311/swiss_knife_encryptor.git
```
7. Install the reqıired libraries:
```bash
pip install -r requirements.txt
```

## Usage

In the directory of the cloned / installed files, open Terminal. Main code architecture is like shown here:
```bash
python main.py <command> <algo/sub-command> [options]
```
(There are some exceptions so use this Readme as a manual)

### Key-Generation

You need to create a pair of keys for asymmetric encryptions. one of them are public and the other one is private key. You need public for integrity-verify and encrypt; and private to decrypt. Main command is like following:
```bash
python main.py generate-keys <algo> --pub <public key name> --priv <private key name> -b <bit size (if available)>
```
The following codes are for generating a random key pair (for the algo you want):
```bash 
python main.py generate-keys rsa --pub rsa_pub.key --priv rsa_priv.key -b 2048
python main.py generate-keys ecc --pub ecc_pub.key --priv ecc_priv.key
python main.py generate-keys ed25519 --pub ed_pub.key --priv ed_priv.key
python main.py generate-keys ecdh --pub ecdh_pub.key --priv ecdh_priv.key
python main.py generate-keys paillier --pub pail_pub.key --priv pail_priv.key -b 2048
python main.py generate-keys schnorr --pub schnorr_pub.key --priv schnorr_priv.key
```
generate-keys is the command to create a random key pair. After that command, you need to specify the algo you want to use (i.e rsa, ecc, echd etc.). Use the --pub and --priv sub-command to create (and specify) keys and their names (you can choose any name for keys, I recommend using .key extension so it won't cause ambigution). In RSA and Paillier, you can specify bit lenghts for versatility.<br>
Important: **NEVER share your private key because it may create security risks for the text /file /disks you encrypted.** Use different key pairs for different encryptions you will use for higher security.
You can also create private and peer keys for ecdh (this is not for encryption but for instead creating a key pair in a non-secured channel):
```bash
python main.py ecdh --privkey my_ecdh_priv.key --peerkey peer_ecdh_pub.key
```
you can (again 😁) give any name and extension to the output files.

### Symmetric Encryption (Text and Files)

These encryptions use key wrapping so you can write any password you want 😎 To encrypt text or files, main command is like following:
Text:
```bash
python main.py encrypt <algo> -t <text> -p <password> -b <bit size (if available)>
```
File:
```bash
python main.py encrypt <algo> -f <file name> -o <output name> -p <password> -b <bit size (if available)>
```
encrypt is the command to encrypt a text or a file. After that command, you need to specify the algo you want to use. -t subcommand is for text and -f is for files. **You need to specify -o subcommand, a file name and extension for file encryption or else it won't work** enter a password after -p and enter the bit size you want to use (if available) after -b. All AES versions, Camellia and ARIA supports specifying bit sizes.<br>
The following codes are for text encryption (for the algo you want):
```bash
python main.py encrypt aes -t "private text" -p "pass123" -b 256
python main.py encrypt aes-gcm -t "private text" -p "pass123" -b 256
python main.py encrypt aes-ctr -t "private text" -p "pass123" -b 256
python main.py encrypt aes-cfb -t "private text" -p "pass123" -b 256
python main.py encrypt aes-ofb -t "private text" -p "pass123" -b 256
python main.py encrypt chacha20 -t "private text" -p "pass123"
python main.py encrypt xchacha20 -t "private text" -p "pass123"
python main.py encrypt camellia -t "private text" -p "pass123" -b 256
python main.py encrypt sm4 -t "private text" -p "pass123"
python main.py encrypt seed -t "private text" -p "pass123"
python main.py encrypt 3des -t "private text" -p "pass123"
python main.py encrypt blowfish -t "private text" -p "pass123"
python main.py encrypt cast5 -t "private text" -p "pass123"
python main.py encrypt fernet -t "private text" -p "pass123"
python main.py encrypt rc4 -t "private text" -p "pass123"
python main.py encrypt twofish -t "private text" -p "pass123"
python main.py encrypt kuznyechik -t "private text" -p "pass123"
python main.py encrypt aria -t "private text" -p "pass123" -b 256
```
The following codes are for file encryption (for the algo you want):
```bash
python main.py encrypt aes -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt aes-gcm -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt aes-ctr -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt aes-cfb -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt aes-ofb -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt chacha20 -f data.txt -o data.enc -p "pass123"
python main.py encrypt xchacha20 -f data.txt -o data.enc -p "pass123"
python main.py encrypt camellia -f data.txt -o data.enc -p "pass123" -b 256
python main.py encrypt sm4 -f data.txt -o data.enc -p "pass123"
python main.py encrypt seed -f data.txt -o data.enc -p "pass123"
python main.py encrypt 3des -f data.txt -o data.enc -p "pass123"
python main.py encrypt blowfish -f data.txt -o data.enc -p "pass123"
python main.py encrypt cast5 -f data.txt -o data.enc -p "pass123"
python main.py encrypt fernet -f data.txt -o data.enc -p "pass123"
python main.py encrypt rc4 -f data.txt -o data.enc -p "pass123"
python main.py encrypt twofish -f data.txt -o data.enc -p "pass123"
python main.py encrypt kuznyechik -f data.txt -o data.enc -p "pass123"
python main.py encrypt aria -f data.txt -o data.enc -p "pass123" -b 256
```

### Symmetric Encryption (Drives)

This is a new and **experimental** module. **DON'T TRY THIS MODULE FOR ENCRYPTING IMPORTANT DATA ON YOUR DRIVES BECAUSE WE DON'T GIVE GUARANTEE YOU CAN RECOVER THE DATA BACK PROPERLY**<br>
Currently, you can encrypt drives with only AES-XTS. The main command is like following:
```bash
python main.py encrypt aes-xts -d <drive path> --header header.img -p <password> -b <bit size> 
```
for drive path, use the drive name if you use Windows and use drive location in Linux/Unix. You may need sudo or root access in order to encrypt/decrypt in Linux/Unix. **IF YOU GIVE SUDO OR ROOT PERMISSIONS TO THE COMMAND, ALWAYS BE CAREFUL YOU DIDN'T WROTE YOUR OWN BOOT DRIVE. YOU CAN LOSE ALL OF YOUR DATA IF YOU DON'T PAY ATTENTION**
```bash
python main.py encrypt aes-xts -d /dev/sdb1 --header header.img -p "pass123" -b 256
python main.py encrypt aes-xts -d D: --header header.img -p "pass123" -b 256
```
Again, this is experimental, so use this at your own risk.
### Asymmetric Encryption (Text and Files)
You can encrypt a text or a file using RSA or Paillier. *You need to generate a key pair using generate-keys command before this step* The main command is like following:
Text:
```bash
python main.py encrypt rsa -t <text> --pubkey <public key>
```
File:
```bash
python main.py encrypt rsa -f <file name> -o <output name> --pubkey <public key>
```
**You need to specify -o subcommand, a file name and extension for file encryption or else it won't work**
```bash
python main.py encrypt rsa -t "private text" --pubkey rsa_pub.key
python main.py encrypt rsa -f data.txt -o data.enc --pubkey rsa_pub.key
python main.py encrypt paillier -t "12345" --pubkey pail_pub.key
python main.py encrypt paillier -f numbers.txt -o numbers.enc --pubkey pail_pub.key
```

### Hybrid Encryption

Hybrid encryption is what real-life messaging apps do. The sender encrypts the text with a symmetric encryption, then it encrypt the key (or in our case the password you wrote) with asymmetric encryption. The receiver decrypts the key of symmetric algorithms cipher and than the cipher itself. It's much safer than only encrypting with symmetric algo but much faster than encrypting with only asymmetric algo.
The main command is like following:
```bash
python main.py encrypt hybrid -f <file name> -o <output name> --pubkey <pubkey> --asy <asymmetric algo> --sym <symmetric algo>
```
```bash
python main.py encrypt hybrid -f big_file.zip -o big_file.enc --pubkey rsa_pub.key --asy rsa --sym aes
```
**You need to specify -o subcommand, a file name and extension for file encryption or else it won't work**

### Symmetric Decryption (Text and Files)

The main command is like following:
Text:
```bash
python main.py decrypt <algo> -t <ciphertext> -p <password> -b  <bit size (if available)>
```
File:
```bash
python main.py decrypt <algo> -f <file name> -o <output name> -p <password> -b <bit size (if available)>
```
Unlike encrypting, the file (-f) is the encrypted file name and the file (-o) is the decrypted file with the extension it was before. So if you encrypted video.mp4 into video.enc, while decrypting write "-f video.enc -o video.mp4".
```bash
python main.py decrypt aes -t "ciphertext_string" -p "pass123" -b 256
python main.py decrypt chacha20 -t "ciphertext_string" -p "pass123"
python main.py decrypt aria -t "ciphertext_string" -p "pass123" -b 256
python main.py decrypt kuznyechik -t "ciphertext_string" -p "pass123" 
python main.py decrypt aes -f data.enc -o data.txt -p "pass123" -b 256
python main.py decrypt chacha20 -f data.enc -o data.txt -p "pass123"
python main.py decrypt aria -f data.enc -o data.txt -p "pass123" -b 256
python main.py decrypt kuznyechik -f data.enc -o data.txt -p "pass123"
```

### Asymmetric and Hybrid Decryption

Asymmetric decrypting is the same as encrypting but instead you need the private key. Main command is like following:
Text:
```bash
python main.py decrypt <algo> -t <ciphertext> --privkey <private key>
```
File:
```bash
python main.py decrypt <algo> -f <file name> -o <output name> --privkey <private key>
```
Unlike encrypting, the file (-f) is the encrypted file name and the file (-o) is the decrypted file with the extension it was before. So if you encrypted video.mp4 into video.enc, while decrypting write "-f video.enc -o video.mp4".
```bash
python main.py decrypt rsa -t "ciphertext_string" --privkey rsa_priv.key
python main.py decrypt rsa -f data.enc -o data.txt --privkey rsa_priv.key
python main.py decrypt paillier -t "ciphertext_string" --privkey pail_priv.key
```
Hybrid decryption is much easier than encryption because you don't need to specify the algos again by hand. It's the same as regular asymmetric file decrytion, all you have to do is write `hybrid` as algo.
```bash
python main.py decrypt hybrid -f big_file.enc -o big_file.zip --privkey rsa_priv.key
```

### Disk Decryption

Main command is like following:
```bash
python main.py decrypt aes-xts -d <drive path> --header header.img -p <password>
```
for drive path, use the drive name if you use Windows and use drive location in Linux/Unix. You may need sudo or root access in order to encrypt/decrypt in Linux/Unix. **IF YOU GIVE SUDO OR ROOT PERMISSIONS TO THE COMMAND, ALWAYS BE CAREFUL YOU DIDN'T WROTE YOUR OWN BOOT DRIVE. YOU CAN LOSE ALL OF YOUR DATA IF YOU DON'T PAY ATTENTION**
```bash
python main.py decrypt aes-xts -d /dev/sdb1 --header header.img -p "pass123"
python main.py decrypt aes-xts -d D: --header header.img -p "pass123"
```

### Signing and Verifying

Signing and encrypting is used to make sure the file is unchanged or not corrupted by using asymmetric algos. The main command is like following:
Signing:
```bash
python main.py sign <algo> -f <file name> --sig <signature file> --privkey <private key>
```
Verifying:
```bash
python main.py verify <algo> -f <file name> --sig <signature file> --pubkey <public key>
```
--sig file is the signature of the -f file (if signing it will be created with the name you specify, if verifying you need to write the signature file).
```bash
python main.py sign rsa -f file.pdf --sig file.sig --privkey rsa_priv.key
python main.py verify rsa -f file.pdf --sig file.sig --pubkey rsa_pub.key
python main.py sign ecc -f file.pdf --sig file.sig --privkey ecc_priv.key
python main.py verify ecc -f file.pdf --sig file.sig --pubkey ecc_pub.key
python main.py sign ed25519 -f file.pdf --sig file.sig --privkey ed_priv.key
python main.py verify ed25519 -f file.pdf --sig file.sig --pubkey ed_pub.key
```

### ZKP (Zero-Knowledge Proof)

ZKP (Zero-Knowledge Proof) is a cryptographic method that lets one party (the prover) prove to another party (the verifier) that a statement is true without revealing any information beyond the statement's validity.
The main command is like following:
Prove:
```bash
python main.py zkp prove --privkey <private key> -m <text>
```
Verify:
```bash
python main.py zkp verify --pubkey <public key> --proof <proof>
```
This algo is also used in cryptocurrency and sign-in without password systems. 

### Nested Encryption

Nested encryption is an encryption which applies two symmetric algo to the file it encrypts as layers. Unlike encrypting, the file (-f) is the encrypted file name and the file (-o) is the decrypted file with the extension it was before. So if you encrypted video.mp4 into video.enc, while decrypting write "-f video.enc -o video.mp4". Main command is like following:
```bash
python main.py nested encrypt --layer1 <algo> --layer2 <algo> -f <file name> -o <output name> -p <password>
python main.py nested decrypt --layer1 <algo> --layer2 <algo> -f <file name> -o <output name> -p <password> 
```
```bash
python main.py nested encrypt --layer1 aes --layer2 chacha20 -f file.txt -o file.nested -p "pass123"
python main.py nested decrypt --layer1 aes --layer2 chacha20 -f file.nested -o file.txt -p "pass123"
```

### Data Shredding

Data shredding is used to make sure the file you want to delete is unrecoverable by any way. Data shredder writes random bytes to the sector where the file was before, so there are no traces left behind. The main command is like following:
```bash
python main.py shred -f <file name> --passes <random byte write number>
```
```bash
python main.py shred -f secret_file.pdf --passes 3
```

### Steganography and Audio Steganography

In terms, Steganograpy isn't a cryptography system, but instead an art. Instead of encrypting a text, it hides the text into the least significant bits in an image or an audio. When you inspect the photo or audio you can't find anything but everything is hid in there 😎. The main command is like following:
```bash
python main.py stego hide -m image -i <image file> -t <text> -o <output file>
python main.py stego extract -m image -i <image file>
```  
```bash
python main.py stego hide -m audio -a <sound file> -t <text> -o <output file>
python main.py stego extract -m audio -a <sound file>
```  
```bash
python main.py stego hide -m image -i image.png -t "Secret Text" -o secret_image.png
python main.py stego extract -m image -i secret_image.png
python main.py stego hide -m audio -a audio.wav -t "Secret Text" -o secret_audio.wav
python main.py stego extract -m audio -a secret_audio.wav
```

### Encode / Decode

Encoding / Decoding is like encrypting / decrypting but in encode you aren't hiding your text or files to be not found, but instead you're changing the characters with their equivalent. **This is not for hiding your info to others because it is much more easier to crack the cipher.** Main command is like following:
```bash
python main.py encode <algo> -t <text>
python main.py encode <algo> -f <file name> -o <output name>
python main.py decode <algo> -t <cipher>
python main.py decode <algo> -f <file name> -o <output name>
```
Unlike encrypting, the file (-f) is the encrypted file name and the file (-o) is the decrypted file with the extension it was before. So if you encrypted video.mp4 into video.enc, while decrypting write "-f video.enc -o video.mp4".
```bash
python main.py encode base64 -t "text"
python main.py encode base64 -f file.bin -o file.b64
python main.py decode base64 -t "bWV0aW4="
python main.py decode base64 -f file.b64 -o file.bin
python main.py encode hex -t "text"
python main.py encode hex -f file.bin -o file.hex
python main.py decode hex -t "6d6574696e"
python main.py decode hex -f file.hex -o file.bin
```

### Hash

Hasing is used to summarize a text/file with no way to turn it back to data. In other words, the file you hashed can't be turned into it's original state again. Main command is like following:
```bash
python main.py hash <algo> -t <text>
python main.py hash <algo> -f <file>
```
Unlike other encryption methods, you don't need an output file or a decryption method. You can't turn that hash into it's original state.
```bash
python main.py hash md5 -t "text"
python main.py hash md5 -f file.txt
python main.py hash sha1 -t "text"
python main.py hash sha1 -f file.txt
python main.py hash sha256 -t "text"
python main.py hash sha256 -f file.txt
python main.py hash sha512 -t "text"
python main.py hash sha512 -f file.txt
python main.py hash blake2b -t "text"
python main.py hash blake2b -f file.txt
python main.py hash blake2s -t "text"
python main.py hash blake2s -f file.txt
python main.py hash ripemd160 -t "text"
python main.py hash ripemd160 -f file.txt
python main.py hash sha3_256 -t "text"
python main.py hash sha3_256 -f file.txt
python main.py hash sha3_512 -t "text"
python main.py hash sha3_512 -f file.txt
```
You can also hash your passwords and Key Derivation Formulas with some other specific hash algos. Unlike the others at top, these methods are designed to be run slow so other persons can't try to hack it easily. These methods are Argon2, Bcrypt, PBKDF2 and Scrypt.
```bash
python main.py hash argon2 -t "parolam123"
python main.py hash argon2 -t "parolam123" --verify "$argon2id$v=19$m=65536,t=3,p=4$..."
python main.py hash bcrypt -t "parolam123"
python main.py hash bcrypt -t "parolam123" --verify "$2b$12$..."
python main.py hash pbkdf2 -t "parolam123" --salt 1234567890abcdef
python main.py hash scrypt -t "parolam123" --salt 1234567890abcdef
```

### HMAC Authenciation

HMAC Authenciation is for securing messages to make sure it isn't corrupted or touched by others. Main command is like following:
```bash
python main.py hmac generate -t <text> -k <private key>
python main.py hmac verify -t <text> -k <private key> --mac <hmac string>
python main.py hmac generate -f <file name> -k <private key>
python main.py hmac verify -f <file name> -k <private key> --mac <hmac string>
```
```bash
python main.py hmac generate -t "text" -k "secret_key"
python main.py hmac verify -t "text" -k "secret_key" --mac "hmac_string"
python main.py hmac generate -f file.txt -k "secret_key"
python main.py hmac verify -f file.txt -k "secret_key" --mac "hmac_string"
```

### PQC (Post-Quantum Cryptography)

This is the most interesting one among them, because these algos considered as *Quantum Resistant*. Even a Quantum PC can't broke these algos. Main command is like following:
```bash
python main.py generate-keys <algo> --pub <public key> --priv <private key>
python main.py encrypt <algo> -t <text> --pubkey <public key>
python main.py decrypt <algo> -t <cipher> --privkey <private key>
python main.py sign <algo> -f <file> --sig <signature file> --privkey <private key>
python main.py verify <algo> -f <file> --sig <signature file> --pubkey <public key>
```
The PQC algos are kyber, dilithium, falcon and sphincs. kyber and dilithium supports key generation; kyber supports encryption/decryption; dilithium, falcon and sphincs supports signing/verifying. you can also use kyber while hybrid encrypting a file.

## whoami

Hello! My name is krateleux (bartu110311). I am a high school student who supports open-source projects and wants to be one of the open-source creators. Any pray for open-source creators and who wants to be one is appreciated. If you find any bugs or issues, you can open an issue. You can also help the project by contributing for the next goals of the project. Thank you!

## License

This project is lisenced with GNU GPLv3. You can read the license from [here](https://github.com/bartu110311/swiss_knife_encryptor?tab=GPL-3.0-1-ov-file)