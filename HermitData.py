# -*- coding: utf-8 -*-
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import psutil
from tkinterdnd2 import TkinterDnD, DND_FILES
import time
import shutil
import subprocess
from tkinter import font
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom
import random
import hashlib
from tkinter import ttk
import pyautogui
import threading
import keyboard
from tkinter import simpledialog

class VideoDecryptorApp:
    def __init__(self, root, vlc_path, password):
        self.root = root
        self.vlc_path = vlc_path
        self.password = password
        self.vlc_process = None
        self.playlist = []

        self.setup_gui()

    def setup_gui(self):
        self.root.title("Drag-and-Drop Video Decryptor")
        self.root.iconbitmap("a.ico")
        drop_area = tk.Label(self.root, text="Drag encrypted files here", width=40, height=10, bg="lightgray")
        drop_area.pack(pady=20)
        drop_area.drop_target_register(DND_FILES)
        drop_area.dnd_bind('<<Drop>>', self.drop_files)

    def decrypt_file(self, file_path, output_path):
        try:
            backend = default_backend()
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                encrypted_data = f.read()
    
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=backend
            )
            key = kdf.derive(self.password.encode())
    
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    
            try:
                padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                data = unpadder.update(padded_data) + unpadder.finalize()
            except Exception as e:
                return
    
            with open(output_path, 'wb') as f:
                f.write(data)
     
            return True
        except:
            return False
            
    def decrypt_dragged_files(self, encryptedfileslist, output_folder):
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        for file in encryptedfileslist:
            if file.endswith('.enc'):
                file_path = file
                output_path = os.path.join(os.getcwd(), output_folder, os.path.basename(file_path[:-4]))
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decryption_success = self.decrypt_file(file_path, output_path)
            if not decryption_success:
                return False
        return True
   
    def is_video_file(self, file_path):
        video_extensions = ['.mp4', '.avi', '.mkv', '.mov', '.flv', '.wmv']
        return any(file_path.lower().endswith(ext) for ext in video_extensions)

    def drop_files(self, event):
        files = self.root.tk.splitlist(event.data)
        sstt = self.decrypt_dragged_files(files, 'see_and_delete')
        if not sstt:
            messagebox.showinfo("Error", f"Incorrect Password!")
            return
        
        decrypted_files = [os.path.join(root, file) for root, _, files in os.walk('see_and_delete') for file in files]
        if all(self.is_video_file(file) for file in decrypted_files):
            self.playlist.extend(decrypted_files)
            self.create_and_play_playlist()

    def create_and_play_playlist(self):
        playlist_file = 'playlist.m3u'
        with open(playlist_file, 'w') as f:
            for video in self.playlist:
                f.write(f"{os.path.abspath(video)}\n")

        self.vlc_process = subprocess.Popen([self.vlc_path, playlist_file, '--play-and-exit'])
        self.root.after(1000, self.check_vlc_process)

    def check_vlc_process(self):
        if self.vlc_process.poll() is None:
            self.root.after(1000, self.check_vlc_process)
        else:
            self.cleanup_playlist()
            self.shred_data_folder()

    def cleanup_playlist(self):
        self.playlist = []
        playlist_file = 'playlist.m3u'
        if os.path.exists(playlist_file):
            os.remove(playlist_file)

    def shred_data_folder(self):
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
                file.flush()  
                os.fsync(file.fileno())  
        
        def shred_file(file_path, passes=3):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            os.remove(file_path)
        
        def process_directory(directory):
            def rename_file(file_path):
                def generate_random_string(length=10):
                    chars = 'äՋՌՍՏՒՓՔՌևঅআইইওউঊঋঌএঐওঔকখগঘঙচছজঝঞটঠডঢণতথদধনপফবভমযরলশষসহড়ঢ়য়அஆஇஈஉஊஎஏஐஒஓஔகஙசஞடணதநபமயரဃငစဆဇ'
                    return ''.join(random.choice(chars) for _ in range(length))
           
                base, ext = os.path.splitext(file_path)
                new_name = generate_random_string(10) + ".garbage"
                new_path = os.path.join(os.path.dirname(file_path), new_name)
                os.rename(file_path, new_path)
                return new_path
            for root, dirs, files in os.walk(directory):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        encrypt_file(file_path)
                        new_file_path = rename_file(file_path)
                        shred_file(new_file_path)
                    except Exception as e:
                        print(f"Error processing file {file_path}: {e}")
        
        data_folder = 'see_and_delete'
        if os.path.exists(data_folder):
            process_directory(data_folder)
        else:
            print(f"{data_folder} does not exist.")   
def calculator():
    def button1_clicked(event=None):
        first_value = First_Value_entry.get()
        second_value = Second_Value_entry.get()
        try:
            num1 = float(first_value)
            num2 = float(second_value)
            result = num1 * num2
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, f'{result}')
        except ValueError:
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, "Enter valid numbers")

    def button2_clicked(event=None):
        first_value = First_Value_entry.get()
        second_value = Second_Value_entry.get()
        try:
            num1 = float(first_value)
            num2 = float(second_value)
            result = num1 / num2
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, f'{result}')
        except ValueError:
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, "Enter valid numbers")
        except ZeroDivisionError:
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, "infinity")

    def button3_clicked(event=None):
        first_value = First_Value_entry.get()
        second_value = Second_Value_entry.get()
        try:
            num1 = float(first_value)
            num2 = float(second_value)
            result = num1 + num2
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, f'{result}')
        except ValueError:
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, "Enter valid numbers")

    def button4_clicked(event=None):
        first_value = First_Value_entry.get()
        second_value = Second_Value_entry.get()
        try:
            num1 = float(first_value)
            num2 = float(second_value)
            result = num1 - num2
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, f'{result}')
        except ValueError:
            Answer.delete(1.0, tk.END)
            Answer.insert(tk.END, "Enter valid numbers")

    root = tk.Tk()
    root.title("Calculator")
    root.geometry("530x580")

    main_frame = tk.Frame(root)
    main_frame.place(relx=0.5, rely=0.5, anchor='center')

    def is_green_or_yellow(r, g, b):
        return (g > r and g > b) or (r > g and g > b)

    def generate_random_dark_color():
        while True:
            r = random.randint(30, 150)
            g = random.randint(30, 150)
            b = random.randint(30, 150)
            if not is_green_or_yellow(r, g, b):
                break
        hex_color = "#{:02x}{:02x}{:02x}".format(r, g, b)
        return hex_color

    def update_all_button_colors():
        for button in buttons_color:
            new_color = generate_random_dark_color()
            button.config(bg=new_color)
        root.after(1000, update_all_button_colors)

    buttons_color = []
    buttons_fonts = []
    fonts_list = ["Ink Free"]

    def update_font():
        choice = random.choice([0, 1])
        if choice == 0:
            for button in buttons_fonts:
                button.config(font=(random.choice(fonts_list), random.randint(23,25)))
            root.after(1000, update_font)
        else:
            random_font = random.choice(fonts_list)
            for button in buttons_fonts:
                button.config(font=(random_font, random.randint(23,25)))
            root.after(3000, update_font)

    font_style = (random.choice(fonts_list), random.randint(23,25))
    button_width = 4
    button_height = 1
    button_pad_x = 1
    button_pad_y = 1

    label = tk.Label(main_frame, text="Calculator", font=font_style, fg="white", padx=20, pady=20)
    label.grid(row=0, column=0, columnspan=4, pady=(0, 10))
    buttons_fonts.append(label)
    buttons_color.append(label)

    First_Value_entry = tk.Entry(main_frame, font=font_style, width=10)
    First_Value_entry.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

    Second_Value_entry = tk.Entry(main_frame, font=font_style, width=10)
    Second_Value_entry.grid(row=2, column=0, columnspan=4, padx=10, pady=10)

    button1 = tk.Button(main_frame, text="X", width=button_width, height=button_height, font=font_style, bg="brown", fg="white", padx=button_pad_x, pady=button_pad_y, command=button1_clicked)
    button2 = tk.Button(main_frame, text="/", width=button_width, height=button_height, font=font_style, bg="brown", fg="white", padx=button_pad_x, pady=button_pad_y, command=button2_clicked)
    button3 = tk.Button(main_frame, text="+", width=button_width, height=button_height, font=font_style, bg="brown", fg="white", padx=button_pad_x, pady=button_pad_y, command=button3_clicked)
    button4 = tk.Button(main_frame, text="-", width=button_width, height=button_height, font=font_style, bg="brown", fg="white", padx=button_pad_x, pady=button_pad_y, command=button4_clicked)

    button1.grid(row=3, column=0, padx=10, pady=10)
    button2.grid(row=3, column=1, padx=10, pady=10)
    button3.grid(row=3, column=2, padx=10, pady=10)
    button4.grid(row=3, column=3, padx=10, pady=10)

    buttons_fonts.extend([button1, button2, button3, button4])
    buttons_color.extend([button1, button2, button3, button4])

    Answer = tk.Text(main_frame, font=font_style, fg="white", padx=20, pady=20, height=1, width=18, wrap=tk.WORD)
    Answer.grid(row=4, column=0, columnspan=4, pady=(0, 10))

    buttons_fonts.append(Answer)
    buttons_color.append(Answer)

    update_font()
    update_all_button_colors()
    root.mainloop()
def start_mouse_wheel_automation(parent_root):
    class MouseWheelAutomation:
        def __init__(self, root):
            self.root = root
            self.root.title("Mouse Wheel Automation")
            self.root.geometry("250x250")

            self.is_running = False
            self.thread = None
            self.wheel_action = None
            self.roll_amount = None
            self.duration = None

            self.create_first_screen()

        def create_first_screen(self):
            for widget in self.root.winfo_children():
                widget.destroy()

            frame = ttk.Frame(self.root, padding="10")
            frame.pack(expand=True, fill=tk.BOTH)

            self.wheel_action = tk.StringVar(value="up")
            ttk.Label(frame, text="Select Mouse Wheel Action:").grid(row=0, column=0, sticky=tk.W)
            ttk.Radiobutton(frame, text="Wheel Up", variable=self.wheel_action, value="up").grid(row=1, column=0, sticky=tk.W)
            ttk.Radiobutton(frame, text="Wheel Down", variable=self.wheel_action, value="down").grid(row=2, column=0, sticky=tk.W)

            ok_button = ttk.Button(frame, text="OK", command=self.create_second_screen)
            ok_button.grid(row=3, column=0, pady=10)

        def create_second_screen(self):
            for widget in self.root.winfo_children():
                widget.destroy()

            frame = ttk.Frame(self.root, padding="10")
            frame.pack(expand=True, fill=tk.BOTH)

            ttk.Label(frame, text="Enter Roll Amount:").grid(row=0, column=0, sticky=tk.W)
            self.roll_amount = tk.StringVar(value="1")
            ttk.Entry(frame, textvariable=self.roll_amount).grid(row=1, column=0)

            ttk.Label(frame, text="Enter Duration Between Rolls (s):").grid(row=2, column=0, sticky=tk.W)
            self.duration = tk.StringVar(value="20")
            ttk.Entry(frame, textvariable=self.duration).grid(row=3, column=0)

            enter_button = ttk.Button(frame, text="Enter", command=self.create_final_screen)
            enter_button.grid(row=4, column=0, pady=10)

        def create_final_screen(self):
            try:
                self.roll_amount = int(self.roll_amount.get())
                self.duration = int(self.duration.get())
            except ValueError:
                tk.messagebox.showerror("Invalid input", "Please enter valid numbers for roll amount and duration.")
                return
            for widget in self.root.winfo_children():
                widget.destroy()
            frame = ttk.Frame(self.root, padding="10")
            frame.pack(expand=True, fill=tk.BOTH)
            ttk.Label(frame, text="Press 'm' to start and 's' to stop the automation.").pack(pady=20)
            keyboard.on_press_key("m", self.start_automation)
            keyboard.on_press_key("s", self.stop_automation)

        def start_automation(self, e=None):
            if not self.is_running:
                self.is_running = True
                self.marker_x, self.marker_y = pyautogui.position() 
                self.thread = threading.Thread(target=self.run_automation)
                self.thread.start()

        def stop_automation(self, e=None):
            self.is_running = False
            if self.thread:
                self.thread.join()

        def run_automation(self):
            while self.is_running:
                pyautogui.moveTo(self.marker_x, self.marker_y)
                amount = self.roll_amount 
                if self.wheel_action.get() == "up":
                    pyautogui.scroll(amount)
                else:
                    pyautogui.scroll(-amount)
                time.sleep(self.duration)

    automation_window = tk.Toplevel(parent_root)
    app = MouseWheelAutomation(automation_window)


    #print(f"Shredded contents of folder {folder_path}")
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
    key = kdf.derive(password.encode())
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
    #print(f"Encrypted and saved {file_path} to {output_path}")
def encrypt_folder(input_folder, output_folder, password, progress_bar, total_files,screen, file_count_label):
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
                screen.update_idletasks()
                print("already")
                continue 

            print("doing")

            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypt_file(file_path, output_path, password)

            encrypted_files += 1
            remaining_files = total_files - encrypted_files
            progress_bar['value'] = (encrypted_files / total_files) * 100
            file_count_label.config(text=f"Encrypted Files: {encrypted_files} / Remaining Files: {remaining_files}")
            
            screen.update_idletasks()
    if encrypted_files > 0:
        messagebox.showinfo("Info", f"Password: {password}")
        screen.destroy()

def decrypt_file(file_path, output_path, password):
    backend = default_backend()
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_data = f.read()
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=backend
        )
        key = kdf.derive(password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        data = unpadder.update(padded_data) + unpadder.finalize()
        with open(output_path, 'wb') as f:
            f.write(data)
        return True
    except: 
        return False
    #print(f"Decrypted and saved {file_path} to {output_path}")
def decrypt_folder(input_folder, output_folder, password, progress_bar, total_files,screen,filed_count_label):
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
                    screen.update_idletasks()
                    print("already")
                    continue 
                print("doing")
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decryption_success = decrypt_file(file_path, output_path, password)

                if not decryption_success:
                    messagebox.showinfo("Error", f"Incorrect Password: {file_path}")
                    
                    screen.destroy()
                    return
                decrypted_files += 1
                progress_bar['value'] = (decrypted_files / total_files) * 100
                remaining_files = total_files-decrypted_files
                filed_count_label.config(text=f"Decrypted Files: {decrypted_files} / Remaining Files: {remaining_files}")
                screen.update_idletasks()
         
    messagebox.showinfo("Info", f"Decryption Completed and saved to {output_folder}")


def button1_clicked(event=None):
    root.iconify()
    create_encrypt_screen()
def button2_clicked(event=None):
    def oks():
        text_widget_frs.delete(1.0, tk.END)

    def on_first_func():
        root.iconify()
        custom_dialog.destroy()
        create_decrypt_screen()

    def on_second_func():
        oks()
        if not main_password_label_entry: 
            return

        password = main_password_label_entry.get()
        if not password: 
            return
        
        root.iconify()
        vlc_path = r"D:\downloads\installedsoftwares\VideoLAN\VLC\vlc.exe"
        result = run_video_decryptor(vlc_path, password)
        if not result:
            messagebox.showinfo("Info", "Incorrect Password")

    def get_and_check_frs():
        session_token_check_label_result_frs = session_token_check_label_entry.get()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token_check_label_result_frs.encode('utf-8'))
        resultfrs = sha256_hash.hexdigest()
        text_widget_frs.delete(1.0, tk.END)
        text_widget_frs.insert(tk.END, resultfrs)
        session_token_check_label_entry.delete(0, tk.END)


    custom_dialog = tk.Toplevel(root)
    custom_dialog.title("Choose Decryption Method")
    custom_dialog.iconbitmap(r"a.ico")
    window_width = 300
    window_height = 550
    screen_width = custom_dialog.winfo_screenwidth()
    screen_height = custom_dialog.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2

    custom_dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
    custom_dialog.transient(root)  


    session_token_check_label = tk.Label(custom_dialog, text="Session Token Password")
    session_token_check_label.pack(pady=10)
    session_token_check_label_entry = tk.Entry(custom_dialog)
    session_token_check_label_entry.pack(pady=10)

    continue_hash_button = tk.Button(custom_dialog, text="Get", command=get_and_check_frs)
    continue_hash_button.pack(pady=10)
    text_widget_frs = tk.Text(custom_dialog, wrap='word', height=3, width=50)
    text_widget_frs.pack(padx=10, pady=10)


    main_password_label = tk.Label(custom_dialog, text="Main Password")
    main_password_label.pack(pady=10)
    main_password_label_entry = tk.Entry(custom_dialog)
    main_password_label_entry.pack(pady=10)
    this_password = main_password_label_entry.get()

    tk.Label(custom_dialog, text="").pack(pady=10)

    tk.Button(custom_dialog, text="Folder Decryption", command=on_first_func).pack(pady=5)
    tk.Button(custom_dialog, text="Stream Decryption", command=on_second_func).pack(pady=5)

def button3_clicked(event=None):
    root.iconify()
    create_shred_screen()
def safe_text_app():
    window = tk.Tk()
    window.title("Safe Text")
    window.iconbitmap(r"a.ico")
    window.geometry("400x300")
    text_area = tk.Text(window, wrap='word', font=("Arial", 12))
    text_area.pack(expand=True, fill='both')
    window.mainloop()
def button4_clicked(event=None):
    root.iconify()
    check_chrome()    
def button5_clicked():
    root.iconify()
    check_hash()
def button6_clicked():
    root.iconify()
    auto_scroll()
def button7_clicked():
    root.iconify()
    calculator()
def button8_clicked():
    password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8')) 
    resultfrst = sha256_hash.hexdigest()     
    resultfrst_str = resultfrst 
    if resultfrst_str == "a3d3f5e32ad03bd705b98f8944fecb058fb35968584a485c7d523e11750369b1":  
        root.iconify()
        vlc_path = r"D:\downloads\installedsoftwares\VideoLAN\VLC\vlc.exe"
        run_video_decryptor(vlc_path, password)
    else:
        messagebox.showinfo("Info", f"Incorrect Password")
def get_total_files(input_folder):
    total_files = 0
    for _, _, files in os.walk(input_folder):
        total_files += len(files)
    return total_files
def create_encrypt_screen():
    def get_entry_values():
        session_token = session_token_entry.get()
        folder_to_encrypt = folder_to_encrypt_entry.get()
        output_folder = output_folder_entry.get()

        messagebox.showinfo("Info", f"Starting to Encrypt {output_folder}")
        progress_bar['maximum'] = 100

        def start_encryption(folder_to_encrypt, output_folder, session_token, progress_bar, screen, file_count_label):
            total_files = get_total_files(folder_to_encrypt)
            if total_files > 0:
                encrypt_folder(folder_to_encrypt, output_folder, session_token, progress_bar, total_files, screen, file_count_label)
        
        threading.Thread(target=start_encryption, args=(folder_to_encrypt, output_folder, session_token, progress_bar, screen, file_count_label)).start()
              
           
 
        session_token = ""
        session_token_entry.delete(0, tk.END)  
        session_token = None
    

    screen = tk.Tk()
    screen.iconbitmap(r"a.ico")  
    screen.title("Encrypt")

    window_width = 400
    window_height = 750
    screen_width = screen.winfo_screenwidth()
    screen_height = screen.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2

    screen.geometry(f"{window_width}x{window_height}+{x}+{y}")
 
    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    def get_and_check_frs():
        session_token_check_label_result_frs = session_token_check_label_entry.get()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token_check_label_result_frs.encode('utf-8'))
        resultfrs = sha256_hash.hexdigest()  
        text_widget_frs.delete(1.0, tk.END)
        text_widget_frs.insert(tk.END, resultfrs)

        session_token_check_label_entry.delete(0, tk.END)

        sha256_hash = None
        resultfrs = None
        session_token_check_label_result_frs = None

        del sha256_hash 
        del resultfrs  
        del session_token_check_label_result_frs
 
    def oks():
        text_widget_frs.delete(1.0, tk.END)

    session_token_check_label = tk.Label(frame, text="SHA-256 Hash")
    session_token_check_label.pack(pady=10)

    session_token_check_label_entry = tk.Entry(frame)
    session_token_check_label_entry.pack(pady=10)


    continue_hash_button = tk.Button(frame, text="Check Hash", command=get_and_check_frs)
    continue_hash_button.pack(pady=10)

    text_widget_frs = tk.Text(frame, wrap='word', height=3, width=50)
    text_widget_frs.pack(padx=10, pady=10)
    text_widget_frs.insert(tk.END, "")

    ok_hash_button = tk.Button(frame, text="ok", command=oks)
    ok_hash_button.pack(pady=10)

    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    large_font = font.Font(size=14)
    session_token_entry = tk.Entry(frame,width = 25, font=large_font)
    session_token_entry.pack(pady=10)

    folder_to_encrypt_label = tk.Label(frame, text="Folder to Encrypt")
    folder_to_encrypt_label.pack(pady=10)
    folder_to_encrypt_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_encrypt_entry))
    folder_to_encrypt_button.pack(pady=10)
    folder_to_encrypt_entry = tk.Entry(frame,width = 25, font=large_font)
    folder_to_encrypt_entry.pack(pady=10)

    output_folder_label = tk.Label(frame, text="Output Folder")
    output_folder_label.pack(pady=10)
    output_folder_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(output_folder_entry))
    output_folder_button.pack(pady=10)
    output_folder_entry = tk.Entry(frame,width = 25, font=large_font)
    output_folder_entry.pack(pady=10)

    continue_button = tk.Button(frame, text="Continue", command=get_entry_values)
    continue_button.pack(pady=10)

    file_count_label = tk.Label(frame, text="Encrypted Files: 0 / Remaining Files: 0")
    file_count_label.pack(pady=10)

    progress_bar = ttk.Progressbar(frame, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    screen.mainloop()
def create_decrypt_screen():
    def get_entry_values_de():
        session_token = session_token_entry.get()
        folder_to_decrypt = folder_to_decrypt_entry.get()
        output_folder = output_folder_entry.get()
 
        messagebox.showinfo("Info", f"Starting to Decrypt {output_folder}")
        
        progress_bar['maximum'] = 100
        def start_encryption(folder_to_decrypt, output_folder, session_token, progress_bar, screen, filed_count_label):
            total_files = get_total_files(folder_to_decrypt)
            if total_files > 0:
                decrypt_folder(folder_to_decrypt, output_folder, session_token, progress_bar, total_files, screen, filed_count_label)
        
        threading.Thread(target=start_encryption, args=(folder_to_decrypt, output_folder, session_token, progress_bar, screen, filed_count_label)).start()

        session_token = ""
        session_token_entry.delete(0, tk.END)  
        session_token = None

      

        
    screen = tk.Tk()
    screen.iconbitmap(r"a.ico")  
    screen.title("Decrypt")


    window_width = 400
    window_height = 750
    screen_width = screen.winfo_screenwidth()
    screen_height = screen.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2

    screen.geometry(f"{window_width}x{window_height}+{x}+{y}")
 


    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')


    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    large_font = font.Font(size=14)
    session_token_entry = tk.Entry(frame,width = 25, font=large_font)
    session_token_entry.pack(pady=10)

    folder_to_decrypt_label = tk.Label(frame, text="Folder to Decrypt")
    folder_to_decrypt_label.pack(pady=10)
    folder_to_decrypt_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_decrypt_entry))
    folder_to_decrypt_button.pack(pady=10)
    folder_to_decrypt_entry = tk.Entry(frame,width = 25, font=large_font)
    folder_to_decrypt_entry.pack(pady=10)

    output_folder_label = tk.Label(frame, text="Output Folder")
    output_folder_label.pack(pady=10)
    output_folder_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(output_folder_entry))
    output_folder_button.pack(pady=10)
    output_folder_entry = tk.Entry(frame,width = 25, font=large_font)
    output_folder_entry.pack(pady=10)

    continue_button = tk.Button(frame, text="Continue", command=get_entry_values_de)
    continue_button.pack(pady=10)

    filed_count_label = tk.Label(frame, text="Decrypted Files: 0 / Remaining Files: 0")
    filed_count_label.pack(pady=10)

    progress_bar = ttk.Progressbar(frame, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)


    screen.mainloop()
def create_shred_screen():
    def shred_data_folder(folder_to_shred, progress_bar, total_files,screen,files_count_label):
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
                file.flush()  
                os.fsync(file.fileno())  
        
        def shred_file(file_path, passes=3):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            os.remove(file_path)
        
        def process_directory(directory):
            def rename_file(file_path):
                def generate_random_string(length=10):
                    chars = 'äՋՌՍՏՒՓՔՌևঅআইইওউঊঋঌএঐওঔকখগঘঙচছজঝঞটঠডঢণতথদধনপফবভমযরলশষসহড়ঢ়য়அஆஇஈஉஊஎஏஐஒஓஔகஙசஞடணதநபமயரဃငစဆဇ'
                    return ''.join(random.choice(chars) for _ in range(length))
           
                base, ext = os.path.splitext(file_path)
                new_name = generate_random_string(10) + ".garbage"
                new_path = os.path.join(os.path.dirname(file_path), new_name)
                os.rename(file_path, new_path)
                return new_path
            shredded_files = 0
            for root, dirs, files in os.walk(directory):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        encrypt_file(file_path)
                        new_file_path = rename_file(file_path)
                        shred_file(new_file_path)
                        shredded_files += 1
                        remaining_files = total_files - shredded_files
                        progress_bar['value'] = (shredded_files / total_files) * 100
                        files_count_label.config(text=f"shredded Files: {shredded_files} / Remaining Files: {remaining_files}")
                        screen.update_idletasks()

                    except Exception as e:
                        print(f"Error processing file {file_path}: {e}")
            messagebox.showinfo("Info", f"Shreded and deleted {folder_to_shred}")
            
        data_folder = folder_to_shred
        if os.path.exists(data_folder):
            process_directory(data_folder)
        else:
            pass

    def on_shred_close():
        screen.destroy()
        global root
        root.deiconify()
        root.attributes('-zoomed', True)
        root.lift()
        
    def get_entry_values_shred():
        folder_to_shred = folder_to_shred_entry.get()
        session_token = session_token_entry.get()

        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token.encode('utf-8')) 
        resultfrst = sha256_hash.hexdigest()    
        resultfrst_str = resultfrst 
        if resultfrst_str == "a3d3f5e32ad03bd705b98f8944fecb058fb35968584a485c7d523e11750369b1": 
            messagebox.showinfo("Info", f"Starting to Shred {folder_to_shred}")
        
            progress_bar['maximum'] = 100

            def start_shredding(folder_to_shred, progress_bar, screen, files_count_label):
                total_files = get_total_files(folder_to_shred)
                if total_files > 0:
                    shred_data_folder(folder_to_shred, progress_bar, total_files,screen, files_count_label)
            
            threading.Thread(target=start_shredding, args=(folder_to_shred, progress_bar, screen, files_count_label)).start()

            #root.deiconify()
        else:
            messagebox.showinfo("Info", f"The session token you entered: '{session_token}' is invalid.")
            screen.destroy()
            root.deiconify()
            
        session_token = ""
        session_token_entry.delete(0, tk.END)  
        resultfrst = None
        session_token = None
        sha256_hash = None


    screen = tk.Tk()
    screen.title("Shred")
    screen.iconbitmap(r"a.ico")  

    window_width = 400
    window_height = 750
    screen_width = screen.winfo_screenwidth()
    screen_height = screen.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2

    screen.geometry(f"{window_width}x{window_height}+{x}+{y}")

    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    def get_and_check_frs():
        session_token_check_label_result_frs = session_token_check_label_entry.get()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token_check_label_result_frs.encode('utf-8'))
        resultfrs = sha256_hash.hexdigest()  
        text_widget_frs.delete(1.0, tk.END)
        text_widget_frs.insert(tk.END, resultfrs)

        session_token_check_label_entry.delete(0, tk.END)

        sha256_hash = None
        resultfrs = None
        session_token_check_label_result_frs = None

        del sha256_hash 
        del resultfrs  
        del session_token_check_label_result_frs
 
    def oks():
        text_widget_frs.delete(1.0, tk.END)

    large_font = font.Font(size=14)
    session_token_check_label = tk.Label(frame, text="SHA-256 Hash")
    session_token_check_label.pack(pady=10)
    session_token_check_label_entry = tk.Entry(frame,width = 25, font=large_font)
    session_token_check_label_entry.pack(pady=10)

    continue_hash_button = tk.Button(frame, text="Check Hash", command=get_and_check_frs)
    continue_hash_button.pack(pady=10)

    text_widget_frs = tk.Text(frame, wrap='word', height=3, width=50)
    text_widget_frs.pack(padx=10, pady=10)
    text_widget_frs.insert(tk.END, "")

    ok_hash_button = tk.Button(frame, text="ok", command=oks)
    ok_hash_button.pack(pady=10)


    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    
    session_token_entry = tk.Entry(frame,width = 25, font=large_font)
    session_token_entry.pack(pady=10)
   

    folder_to_shred_label = tk.Label(frame, text="Folder to Shred")
    folder_to_shred_label.pack(pady=10)
    folder_to_shred_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_shred_entry))
    folder_to_shred_button.pack(pady=10)
    folder_to_shred_entry = tk.Entry(frame,width = 25, font=large_font)
    folder_to_shred_entry.pack(pady=10)
    
    submit_button = tk.Button(frame, text="Submit", command=get_entry_values_shred)
    submit_button.pack(pady=20)
    exit_button = tk.Button(frame, text="EXIT", command=on_shred_close)
    exit_button.pack(pady=20)

    files_count_label = tk.Label(frame, text="Shredded Files: 0 / Remaining Files: 0")
    files_count_label.pack(pady=10)

    progress_bar = ttk.Progressbar(frame, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    screen.mainloop()

fonts_list = ["Arial Black", "Bahnschrift Light", "Comic Sans MS", "Constantia", "Franklin Gothic Medium", "Ink Free", "Segoe Print", "Segoe Script","Gabriola", "Ink Free", "Segoe Print", "Segoe Script", "Alien Encounters"]

def check_chrome():
    def read_previous_values(filename="network_usage.txt"):
        try:
            with open(filename, "r") as file:
                lines = file.readlines()
                
                zerot = sentt = recvt = 0.0
      
                if len(lines) > 0:
                    zerot = float(lines[0].strip())
                if len(lines) > 1:
                    sentt = float(lines[1].strip())
                if len(lines) > 2:
                    recvt = float(lines[2].strip())
        except FileNotFoundError:
  
            zerot = sentt = recvt = 0.0
        except ValueError:
           
            zerot = sentt = recvt = 0.0
            print("Warning: One or more values in the file are not valid numbers.")
        return zerot, sentt, recvt

    def write_values(zerot, sentt, recvt, filename="network_usage.txt"):
        with open(filename, "w") as file:
            file.write(f"{zerot:.2f}\n")
            file.write(f"{sentt:.2f}\n")
            file.write(f"{recvt:.2f}\n")

    def get_network_io():
        net_io = psutil.net_io_counters()
        return net_io.bytes_sent, net_io.bytes_recv
    
    def update_time():
        current_time = time.strftime('%H:%M:%S')
        time_label.config(text=current_time)
        root.after(1000, update_time)
    
    def main():
        interval = 1
        global zerot, sentt, recvt  
        sent_prev, recv_prev = get_network_io()
        
        while True:
            time.sleep(interval)
            sent_curr, recv_curr = get_network_io()
            
            sent = sent_curr - sent_prev
            recv = recv_curr - recv_prev
            
            zerot += (sent / (1024 * 1024)) + (recv / (1024 * 1024))
            sentt += (sent / (1024 * 1024))
            recvt += (recv / (1024 * 1024))

            int1_label.config(text=f"{zerot:.2f}")
            int2_label.config(text=f"{sentt:.2f}")
            int3_label.config(text=f"{recvt:.2f}")

            sent_prev, recv_prev = sent_curr, recv_curr
            write_values(zerot, sentt, recvt)
    
    def start_main_thread():
        main_thread = Thread(target=main)
        main_thread.daemon = True 
        main_thread.start()

    root = tk.Tk()
    root.title("Data Usage")
    root.iconbitmap(r"a.ico") 
    window_width = 250
    window_height = 350
    
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    digital_font= (random.choice(fonts_list), random.randint(18, 20))

    fixed_time = time.strftime('%H:%M:%S')
    fixed_time_label = tk.Label(root, text=fixed_time, font=digital_font)
    fixed_time_label.pack(pady=10)
    
    time_label = tk.Label(root, text="", font=digital_font, fg='white')
    time_label.pack(pady=20)
    
    int1_label = tk.Label(root, text="0", font=digital_font, fg='white')
    int1_label.pack(pady=5)
    
    int2_label = tk.Label(root, text="0", font=digital_font, fg='white')
    int2_label.pack(pady=5)
    
    int3_label = tk.Label(root, text="0", font=digital_font, fg='white')
    int3_label.pack(pady=5)
    buttons.extend([time_label,int1_label,int2_label,int3_label])

    global zerot, sentt, recvt
    zerot, sentt, recvt = read_previous_values()
    
    start_main_thread()
    update_time()
    root.mainloop()

def check_hash():

    screen = tk.Tk()
    screen.title("Encrypt")
    screen.geometry("1280x1080")

    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    session_token_check_label = tk.Label(frame, text="SHA-256 Hash")
    session_token_check_label.pack(pady=10)
    session_token_check_label_entry = tk.Entry(frame)
    session_token_check_label_entry.pack(pady=10)

    def get_and_check_frs():
        session_token_check_label_result_frs = session_token_check_label_entry.get()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token_check_label_result_frs.encode('utf-8'))
        resultfrs = sha256_hash.hexdigest()  
        text_widget_frs.delete(1.0, tk.END)
        text_widget_frs.insert(tk.END, resultfrs)

        session_token_check_label_entry.delete(0, tk.END)

        sha256_hash = None
        resultfrs = None
        session_token_check_label_result_frs = None

        del sha256_hash 
        del resultfrs  
        del session_token_check_label_result_frs
 
    def oks():
        text_widget_frs.delete(1.0, tk.END)

    continue_hash_button = tk.Button(frame, text="Check Hash", command=get_and_check_frs)
    continue_hash_button.pack(pady=10)

    text_widget_frs = tk.Text(frame, wrap='word', height=3, width=50)
    text_widget_frs.pack(padx=10, pady=10)
    text_widget_frs.insert(tk.END, "")

    ok_hash_button = tk.Button(frame, text="ok", command=oks)
    ok_hash_button.pack(pady=10)
def auto_scroll():
    start_mouse_wheel_automation(root)
def run_video_decryptor(vlc_path, password):
    root = TkinterDnD.Tk()
    app = VideoDecryptorApp(root, vlc_path, password)
    root.mainloop()

def choose_folder(entry):
    folder = filedialog.askdirectory()
    entry.delete(0, tk.END)
    entry.insert(0, folder)
def print_fields(*entries):
    for entry in entries:
        print(entry.get())

root = tk.Tk()
root.title("Hermit Data Manager")
root.geometry("1280x1080")

root.iconbitmap(r"a.ico")  

main_frame = tk.Frame(root)
main_frame.place(relx=0.5, rely=0.5, anchor='center')

def is_green_or_yellow(r, g, b):
    return (g > r and g > b) or (r > g and g > b)
def generate_random_dark_color():
    while True:
        r = random.randint(30, 150)
        g = random.randint(30, 150)
        b = random.randint(30, 150)

        if not is_green_or_yellow(r, g, b):
            break

    hex_color = "#{:02x}{:02x}{:02x}".format(r, g, b)
    return hex_color
def update_all_button_colors():
    for button in buttons:
        new_color = generate_random_dark_color()
        button.config(bg=new_color)
    root.after(1000, update_all_button_colors)

buttons = []


def update_font():
    choice = random.choice([0, 1])
    if choice == 0:
        for button in buttons:
            button.config(font=(random.choice(fonts_list), random.randint(18, 20)))
        root.after(1000, update_font)
    else:
        random_font = random.choice(fonts_list)
        for button in buttons:
            button.config(font=(random_font, random.randint(18, 20)))
        root.after(3000, update_font)
        
font_style = (random.choice(fonts_list), random.randint(18, 20))
button_width = 10
button_width_extend = 80
button_height = 2
button_pad_x = 5
button_pad_y = 5

label = tk.Label(main_frame, text="Saqlain has always been Nasty Boy.", font=font_style, fg="white", padx=20, pady=20)
label.grid(row=0, column=0, columnspan=4, pady=(0, 10))
buttons.extend([label])

button1 = tk.Button(main_frame, text="Encrypt", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button1_clicked)
button2 = tk.Button(main_frame, text="Decrypt", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button2_clicked)
button3 = tk.Button(main_frame, text="Shred", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button3_clicked)
button4 = tk.Button(main_frame, text="Chrome\nData Usage", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button4_clicked)

button1.grid(row=1, column=0, padx=10, pady=10)
button2.grid(row=1, column=1, padx=10, pady=10)
button3.grid(row=1, column=2, padx=10, pady=10)
button4.grid(row=1, column=3, padx=10, pady=10)

buttons.extend([button1, button2, button3, button4])

button5 = tk.Button(main_frame, text="Safe\nText", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=safe_text_app)
button6 = tk.Button(main_frame, text="Auto\nScroll", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button6_clicked)
button7 = tk.Button(main_frame, text="Calculator", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button7_clicked)
#button8 = tk.Button(main_frame, text="Stream\nDecryption", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button8_clicked)


button5.grid(row=2, column=0, padx=10, pady=10)
button6.grid(row=2, column=1, padx=10, pady=10)
button7.grid(row=2, column=2, padx=10, pady=10)
#button8.grid(row=2, column=3, padx=10, pady=10)

buttons.extend([button5, button6, button7])

label = tk.Label(main_frame, text="Is somebody gonna match his freak?", font=font_style, fg="white", padx=20, pady=20)
label.grid(row=3, column=0, columnspan=4, pady=(0, 10))
buttons.extend([label])

update_font()
update_all_button_colors()

root.mainloop()



