# -*- coding: utf-8 -*-
import os
import uuid
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import tkinter as tk
from tkinter import filedialog
#root = tk.Tk()
#root.withdraw()  


def password_to_hex_key(password):
    hash_object = hashlib.sha256(password.encode())
    return hash_object.hexdigest()

def create_fixed_iv(iv):
    iv = iv.ljust(16)[:16]
    return iv.encode('utf-8')

def encrypt_file(input_file, output_file, password,iv):
    key_hex = password_to_hex_key(password)
    key = bytes.fromhex(key_hex)
    iv = create_fixed_iv(iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    print(f"Encrypted and saved {input_file} to {output_file}")


def encrypt_folder(input_folder, output_folder, password,iv):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder {output_folder}")
    encrypted_files = 0
    for root, dirs, files in os.walk(input_folder):
        
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, input_folder)
            output_path = os.path.join(output_folder, relative_path + '.enc')
            if os.path.exists(output_path):
                encrypted_files += 1
                continue 
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypt_file(file_path, output_path, password,iv)
            encrypted_files += 1
    if encrypted_files > 0:
        print("")
    return(encrypted_files)

def decrypt_file(input_file, output_file, password,iv):
    key_hex = password_to_hex_key(password)
    key = bytes.fromhex(key_hex)
    iv = create_fixed_iv(iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted and saved {input_file} to {output_file}")

def decrypt_folder(input_folder, output_folder, password):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder {output_folder}")
    decrypted_files = 0
    
    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, input_folder)
                output_path = os.path.join(output_folder, relative_path[:-4])
                if os.path.exists(output_path):
                    decrypted_files += 1
                    continue 
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decryption_success = decrypt_file(file_path, output_path, password, iv)
                if not decryption_success:
                    print(file)
                decrypted_files += 1

    print("Info", f"Decryption Completed and saved to {output_folder}")
    return(decrypted_files)



def shred_data_folder(folder_to_shred):
    def encrypt_file(file_path):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(file_path, 'wb') as file:
            file.write(iv + ciphertext)

    def shred_file(file_path, passes=7):
        file_size = os.path.getsize(file_path)
        with open(file_path, 'r+b') as file:
            for _ in range(passes):
                file.seek(0)
                file.write(os.urandom(file_size))
        os.remove(file_path)

    def process_directory(directory):
        shredded_files = 0
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    random_name = str(uuid.uuid4())
                    new_file_path = os.path.join(root, random_name)
                    os.rename(file_path, new_file_path)
                    encrypt_file(new_file_path)
                    shred_file(new_file_path)
                    shredded_files += 1
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
        return shredded_files

    data_folder = folder_to_shred
    if os.path.exists(data_folder):
        shredded_files = process_directory(data_folder)
        return shredded_files
    else:
        print(f"Folder does not exist: {folder_to_shred}")





def encrypt_action():
    password = password_entry.get()
    iv = iv_entry.get()
    input_folder_en = filedialog.askdirectory()
    output_folder_en = filedialog.askdirectory()
    start_time = time.time()
    total_files = encrypt_folder(input_folder_en, output_folder_en, password,iv)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"{password} Time taken : {execution_time} files: {total_files} each file: {execution_time / total_files:.2f} seconds")



def decrypt_action():
    password = password_entry.get()
    iv = iv_entry.get()
    input_folder_de = filedialog.askdirectory() 
    output_folder_de = filedialog.askdirectory() 
    start_time = time.time()
    total_files = decrypt_folder(input_folder_de, output_folder_de, password,iv)
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"{password} Time taken : {execution_time} files: {total_files} each file: {execution_time / total_files:.2f} seconds")


def shred_action():
    folder_to_shred = filedialog.askdirectory()
    start_time = time.time() 
    total_files =shred_data_folder(folder_to_shred)
    end_time = time.time()
    print(f"Shreded:{folder_to_shred}")
    execution_time = end_time - start_time
    print(f"Time taken : {execution_time} files: {total_files} each file: {execution_time / total_files:.2f} seconds")


root = tk.Tk()
root.title("Simple UI")

root.geometry("400x450")

label1 = tk.Label(root, text="Password:", font=("Arial", 14))
label1.pack(pady=5)

password_entry = tk.Entry(root, width=40, font=("Arial", 14), show="*")
password_entry.pack(pady=5)

label2 = tk.Label(root, text="IV:", font=("Arial", 14))
label2.pack(pady=5)

iv_entry = tk.Entry(root, width=40, font=("Arial", 14))
iv_entry.pack(pady=5)

button_en = tk.Button(root, text="Encrypt", command=encrypt_action, width=15, height=2, font=("Arial", 14))
button_en.pack(pady=10)

button_de = tk.Button(root, text="Decrypt", command=decrypt_action, width=15, height=2, font=("Arial", 14))
button_de.pack(pady=10)

button_sh = tk.Button(root, text="Shred", command=shred_action, width=15, height=2, font=("Arial", 14))
button_sh.pack(pady=10)

root.mainloop()
