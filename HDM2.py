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
from tkinter import ttk
from tkinter import filedialog
import threading

#root = tk.Tk()
#root.withdraw()  
#Time taken : 2161.47767663002 files: 26744 each file: 0.08 seconds

def password_to_hex_key(password):
    hash_object = hashlib.sha256(password.encode())
    return hash_object.hexdigest()

def create_fixed_iv(iv):
    iv = iv.ljust(16)[:16]
    return iv.encode('utf-8')

def encrypt_file(input_file, output_file, password,iv):
    try:
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
        return True
    except Exception as e:
        print(e)
        return False
    #print(f"Encrypted and saved {input_file} to {output_file}")


def encrypt_folder(input_folder, output_folder, password,iv,total_files,progress_bar,file_count_label):
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
                progress_bar['value'] = (encrypted_files / total_files) * 100
                remaining_files = total_files-encrypted_files
                file_count_label.config(text=f"Encrypted Files: {encrypted_files} / Remaining Files: {remaining_files}")
                continue 
  
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypt_file(file_path, output_path, password,iv)
            encrypted_files += 1
            remaining_files = total_files - encrypted_files
            progress_bar['value'] = (encrypted_files / total_files) * 100
            file_count_label.config(text=f"Encrypted Files: {encrypted_files} / Remaining Files: {remaining_files}")
    if encrypted_files > 0:
        print("")
    return(encrypted_files)

def decrypt_file(input_file, output_file, password,iv):
    try:
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
        return True
    except Exception as e:
        print(e)
        return False
    #print(f"Decrypted and saved {input_file} to {output_file}")

def decrypt_folder(input_folder, output_folder, password,iv,total_files,progress_bar,filed_count_label):
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
                    progress_bar['value'] = (decrypted_files / total_files) * 100
                    remaining_files = total_files-decrypted_files
                    filed_count_label.config(text=f"Decrypted Files: {decrypted_files} / Remaining Files: {remaining_files}")
                    continue 
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decryption_success = decrypt_file(file_path, output_path, password, iv)
                if not decryption_success:
                    print(file)
                decrypted_files += 1
                progress_bar['value'] = (decrypted_files / total_files) * 100
                remaining_files = total_files-decrypted_files
                filed_count_label.config(text=f"Decrypted Files: {decrypted_files} / Remaining Files: {remaining_files}")
                
    print("Info", f"Decryption Completed and saved to {output_folder}")
    return(decrypted_files)



def shred_data_folder(folder_to_shred,total_files,progress_bar,file_count_label):
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

    def shred_file(file_path, passes=3):
        file_size = os.path.getsize(file_path)
        with open(file_path, 'r+b') as file:
            for _ in range(passes):
                file.seek(0)
                file.write(os.urandom(file_size))
        os.remove(file_path)

    def process_directory(directory,total_files,progress_bar,files_count_label):
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
                    remaining_files = total_files - shredded_files
                    progress_bar['value'] = (shredded_files / total_files) * 100
                    files_count_label.config(text=f"shredded Files: {shredded_files} / Remaining Files: {remaining_files}")
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
        return shredded_files

    data_folder = folder_to_shred
    if os.path.exists(data_folder):
        shredded_files = process_directory(data_folder,total_files,progress_bar,file_count_label)
        return shredded_files
    else:
        print(f"Folder does not exist: {folder_to_shred}")



def get_total_files(input_folder):
    total_files = 0
    for _, _, files in os.walk(input_folder):
        total_files += len(files)
    return total_files

def encrypt_action():
    password = password_entry.get()
    iv = iv_entry.get()
     
    input_folder_en = filedialog.askdirectory()
    output_folder_en = filedialog.askdirectory()
    total_files = get_total_files(input_folder_en)

   
    def start_encryption(input_folder_en, output_folder_en, password, iv,total_files, progress_bar, file_count_label): 
        if total_files > 0:
            encrypt_folder(input_folder_en, output_folder_en, password, iv, total_files, progress_bar, file_count_label)
    
    threading.Thread(target=start_encryption, args=(input_folder_en, output_folder_en, password, iv,total_files, progress_bar, file_count_label)).start()
      
    print(f"Password: {password} files: {total_files} ")



def decrypt_action():
    password = password_entry.get()
    iv = iv_entry.get()
    input_folder_de = filedialog.askdirectory() 
    output_folder_de = filedialog.askdirectory() 
    total_files = get_total_files(input_folder_de)
    def start_encryption(input_folder_de, output_folder_de, password, iv, total_files, progress_bar, filed_count_label):
        if total_files > 0:
            decrypt_folder(input_folder_de, output_folder_de, password, iv, total_files, progress_bar, filed_count_label)
    
    threading.Thread(target=start_encryption, args=(input_folder_de, output_folder_de, password, iv, total_files, progress_bar, file_count_label)).start()
      
    

    print(f"Password: {password} files: {total_files} ")


def shred_action():
    folder_to_shred = filedialog.askdirectory()

    total_files = get_total_files(folder_to_shred)

    def start_shredding(folder_to_shred, total_files, progress_bar,  files_count_label):
        total_files = get_total_files(folder_to_shred)
        if total_files > 0:
            shred_data_folder(folder_to_shred, total_files, progress_bar, files_count_label)
    
    threading.Thread(target=start_shredding, args=(folder_to_shred,total_files, progress_bar,file_count_label)).start()

    print(f"files: {total_files} Shreded:{folder_to_shred}")
 

root = tk.Tk()
root.title("Simple UI")

root.geometry("400x500")

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

file_count_label = tk.Label(root, text="Encrypted Files: 0 / Remaining Files: 0")
file_count_label.pack(pady=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_bar.pack(pady=10)



root.mainloop()
