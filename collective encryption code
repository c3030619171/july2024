"""
Saqlain Hermit commited this file.  Hello Everyone, in this file i have added collected code for different purposes. 
you can seperate it based on your own needs

Prompt for Encryption Schme:
Can you provide a code example for AES encryption in CBC mode that includes Google Drive file handling,
uses Scrypt for key derivation,
and includes PKCS7 padding for secure encryption and decryption of files?
LINE 17  : encryption code
LINE 90  : decryption code
Line 135 : derive password using knemonics
line 167 : rename files in drive

-----------------------------------------------------------------------
ENCRYPTION
"""
import os
from os import urandom
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes, iterations: int = 2**14):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=iterations,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, output_path, password):
    backend = default_backend()
    salt = urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )
    key = kdf.derive(password)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

def process_directory(directory, password, output_folder):
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(file_path, directory)
            output_path = os.path.join(output_folder, relative_path + '.enc')
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypt_file(file_path, output_path, password)

# Define paths
input_folder = '/content/drive/My Drive/all_data'  # Your folder name here
output_folder = '/content/drive/My Drive/all_encrypted_data'
os.makedirs(output_folder, exist_ok=True)

# Password for encryption
password = input("Enter password for encryption: ")
# Encrypt files
process_directory(input_folder, password.encode(), output_folder)
print("Encryption complete.")

"""
Encryption Code Ends Here


------------------------------------------------------------------------------------------------

Decryption Code Start here
"""
def decrypt_file(encrypted_file_path, password, output_folder):
    with open(encrypted_file_path, 'rb') as f:
        salt = f.read(16)  # First 16 bytes are the salt
        iv = f.read(16)    # Next 16 bytes are the IV
        ciphertext = f.read()  # The rest is the ciphertext

    # Derive key
    key = derive_key(password, salt)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad using PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save decrypted file
    decrypted_file_path = os.path.join(output_folder, os.path.basename(encrypted_file_path).replace('.enc', ''))
    os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

def process_decryption(directory, password, output_folder):
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.enc'):
                encrypted_file_path = os.path.join(dirpath, filename)
                decrypt_file(encrypted_file_path, password.encode(), output_folder)

# Define paths
encrypted_folder = '/content/drive/My Drive/all_encrypted_data'
decrypted_folder = '/content/drive/My Drive/all_decrypted_data'
os.makedirs(decrypted_folder, exist_ok=True)

# Password for decryption (should match the encryption password)
password = input("Enter password for decryption: ")

# Decrypt files
process_decryption(encrypted_folder, password.encode(), decrypted_folder)
print("Decryption complete.")
"""
-------------------------------------------------------

knemonic password generator
"""
from sympy import prime
import hashlib

n_primes = int(input())
iterations = int(input())
lucky_number = int(input())

primes = [prime(i) for i in range(1, n_primes + 1)]

for prime_number in primes:
    lucky_number *= prime_number

result_str = str(lucky_number)

def repeated_hash(input_value, iterations):
    hash_value = input_value.encode()
    for _ in range(iterations):
        hash_value = hashlib.sha256(hash_value).digest()
    return hash_value.hex()

final_hash = repeated_hash(result_str, iterations)
print(final_hash.hex())

"""
-----------------------------------------------------------------------

rename and overwrite files in drive
"""


import os
import shutil

def overwrite_with_encrypted_files(original_folder, encrypted_folder):
    for dirpath, _, filenames in os.walk(original_folder):
        for filename in filenames:
            original_file_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(original_file_path, original_folder)
            encrypted_file_path = os.path.join(encrypted_folder, relative_path + '.enc')

            if os.path.exists(encrypted_file_path):
                shutil.copyfile(encrypted_file_path, original_file_path)
                print("yes")
                new_file_path = original_file_path + '.enc'
                os.rename(original_file_path, new_file_path)

original_folder = '/content/drive/My Drive/all_data'
encrypted_folder = '/content/drive/My Drive/all_encrypted_data'

overwrite_with_encrypted_files(original_folder, encrypted_folder)
print("Overwrite and rename complete.")
"""
