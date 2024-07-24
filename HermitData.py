import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import psutil
import tkinter as tk
import time
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

            # Set up keyboard listeners
            keyboard.on_press_key("m", self.start_automation)
            keyboard.on_press_key("s", self.stop_automation)

        def start_automation(self, e=None):
            if not self.is_running:
                self.is_running = True
                self.marker_x, self.marker_y = pyautogui.position()  # Get current mouse position
                self.thread = threading.Thread(target=self.run_automation)
                self.thread.start()

        def stop_automation(self, e=None):
            self.is_running = False
            if self.thread:
                self.thread.join()

        def run_automation(self):
            while self.is_running:
                pyautogui.moveTo(self.marker_x, self.marker_y)
                amount = self.roll_amount  # Use the captured roll amount
                if self.wheel_action.get() == "up":
                    pyautogui.scroll(amount)
                else:
                    pyautogui.scroll(-amount)
                time.sleep(self.duration)

    automation_window = tk.Toplevel(parent_root)
    app = MouseWheelAutomation(automation_window)
def shred_file(file_path, passes=3):
    if os.path.isfile(file_path):
        length = os.path.getsize(file_path)
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(file_path)
        print(f"Shredded and deleted {file_path}")
def shred_folder(folder_path, passes=3):
    for root, _, files in os.walk(folder_path, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            shred_file(file_path, passes)
    print(f"Shredded contents of folder {folder_path}")
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
    print(f"Encrypted and saved {file_path} to {output_path}")
def encrypt_folder(input_folder, output_folder, password):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder {output_folder}")
    for root, dirs, files in os.walk(input_folder):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, input_folder)
            output_path = os.path.join(output_folder, relative_path + '.enc')
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypt_file(file_path, output_path, password)
    print(f"Encryption complete. Encrypted files saved to {output_folder}")
def decrypt_file(file_path, output_path, password):
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
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    data = unpadder.update(padded_data) + unpadder.finalize()
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"Decrypted and saved {file_path} to {output_path}")
def decrypt_folder(input_folder, output_folder, password):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder {output_folder}")
    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, input_folder)
                output_path = os.path.join(output_folder, relative_path[:-4])  # Remove '.enc'
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decrypt_file(file_path, output_path, password)
    print(f"Decryption complete. Decrypted files saved to {output_folder}")

def button1_clicked(event=None):
    root.iconify()
    create_encrypt_screen()
def button2_clicked(event=None):
    root.iconify()
    create_decrypt_screen()
def button3_clicked(event=None):
    root.iconify()
    create_shred_screen()
def button4_clicked(event=None):
    root.iconify()
    check_chrome()    
def button5_clicked():
    root.iconify()
    check_hash()
def button6_clicked():
    root.iconify()
    auto_scroll()

def create_encrypt_screen():
    def get_entry_values():
        session_token = session_token_entry.get()
        folder_to_encrypt = folder_to_encrypt_entry.get()
        output_folder = output_folder_entry.get()

        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token.encode('utf-8')) 
        resultfrst = sha256_hash.hexdigest()     
        resultfrst_str = resultfrst 
        if resultfrst_str == "a3d3f5e32ad03bd705b98f8944fecb058fb35968584a485c7d523e11750369b1":  
            messagebox.showinfo("Info", f"Starting to Encrypt {output_folder}")
            encrypt_folder(folder_to_encrypt, output_folder, session_token)
            messagebox.showinfo("Info", f"Encryption Completed and saved to {output_folder}")
            screen.destroy()            
        else:
            screen.destroy()
            messagebox.showinfo("Info", f"The session token you entered: '{session_token}' is invalid.")
            

        session_token = ""
        session_token_entry.delete(0, tk.END)  
        resultfrst = None
        session_token = None
        sha256_hash = None

    screen = tk.Tk()
    screen.title("Encrypt")
    screen.geometry("1280x1080")

    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    session_token_entry = tk.Entry(frame)
    session_token_entry.pack(pady=10)

    folder_to_encrypt_label = tk.Label(frame, text="Folder to Encrypt")
    folder_to_encrypt_label.pack(pady=10)
    folder_to_encrypt_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_encrypt_entry))
    folder_to_encrypt_button.pack(pady=10)
    folder_to_encrypt_entry = tk.Entry(frame)
    folder_to_encrypt_entry.pack(pady=10)

    output_folder_label = tk.Label(frame, text="Output Folder")
    output_folder_label.pack(pady=10)
    output_folder_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(output_folder_entry))
    output_folder_button.pack(pady=10)
    output_folder_entry = tk.Entry(frame)
    output_folder_entry.pack(pady=10)

    continue_button = tk.Button(frame, text="Continue", command=get_entry_values)
    continue_button.pack(pady=10)

    screen.mainloop()
def create_decrypt_screen():
    def get_entry_values_de():
        session_token = session_token_entry.get()
        folder_to_decrypt = folder_to_decrypt_entry.get()
        output_folder = output_folder_entry.get()
        sha256_hash = hashlib.sha256()
        sha256_hash.update(session_token.encode('utf-8')) 
        resultfrst = sha256_hash.hexdigest()     
        resultfrst_str = resultfrst 
        if resultfrst_str == "a3d3f5e32ad03bd705b98f8944fecb058fb35968584a485c7d523e11750369b1":  
            messagebox.showinfo("Info", f"Starting to Decrypt {output_folder}")
            decrypt_folder(folder_to_decrypt, output_folder, session_token)
            messagebox.showinfo("Info", f"Decryption Completed and saved to {output_folder}")
            screen.destroy()
        else:
            screen.destroy()
            messagebox.showinfo("Info", f"The session token you entered: '{session_token}' is invalid.")
            

        session_token = ""
        session_token_entry.delete(0, tk.END)  
        resultfrst = None
        session_token = None
        sha256_hash = None
      

        
    screen = tk.Tk()
    screen.title("Decrypt")
    screen.geometry("1280x1080")

    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')


    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    session_token_entry = tk.Entry(frame)
    session_token_entry.pack(pady=10)

    folder_to_decrypt_label = tk.Label(frame, text="Folder to Decrypt")
    folder_to_decrypt_label.pack(pady=10)
    folder_to_decrypt_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_decrypt_entry))
    folder_to_decrypt_button.pack(pady=10)
    folder_to_decrypt_entry = tk.Entry(frame)
    folder_to_decrypt_entry.pack(pady=10)

    output_folder_label = tk.Label(frame, text="Output Folder")
    output_folder_label.pack(pady=10)
    output_folder_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(output_folder_entry))
    output_folder_button.pack(pady=10)
    output_folder_entry = tk.Entry(frame)
    output_folder_entry.pack(pady=10)

    continue_button = tk.Button(frame, text="Continue", command=get_entry_values_de)
    continue_button.pack(pady=10)

    screen.mainloop()
def create_shred_screen():
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
            shred_folder(folder_to_shred, passes=3)
            print("Folder to shred:", folder_to_shred)
            messagebox.showinfo("Info", f"Shreded and deleted {folder_to_shred}")
            screen.destroy()
            root.deiconify()
        else:
            
            screen.destroy()
            root.deiconify()
            messagebox.showinfo("Info", f"The session token you entered: '{session_token}' is invalid.")
            
        session_token = ""
        session_token_entry.delete(0, tk.END)  
        resultfrst = None
        session_token = None
        sha256_hash = None


    screen = tk.Tk()
    screen.title("Shred")
    screen.geometry("1280x1080")

    frame = tk.Frame(screen)
    frame.place(relx=0.5, rely=0.5, anchor='center')


    session_token_label = tk.Label(frame, text="Session Token")
    session_token_label.pack(pady=10)
    session_token_entry = tk.Entry(frame)
    session_token_entry.pack(pady=10)
   

    folder_to_shred_label = tk.Label(frame, text="Folder to Shred")
    folder_to_shred_label.pack(pady=10)
    folder_to_shred_button = tk.Button(frame, text="Choose Folder", command=lambda: choose_folder(folder_to_shred_entry))
    folder_to_shred_button.pack(pady=10)
    folder_to_shred_entry = tk.Entry(frame)
    folder_to_shred_entry.pack(pady=10)
    
    submit_button = tk.Button(frame, text="Submit", command=get_entry_values_shred)
    submit_button.pack(pady=20)
    exit_button = tk.Button(frame, text="EXIT", command=on_shred_close)
    exit_button.pack(pady=20)

    screen.mainloop()
def check_chrome():
    def get_network_io():
        net_io = psutil.net_io_counters()
        return net_io.bytes_sent, net_io.bytes_recv
    
    def update_time():
       current_time = time.strftime('%H:%M:%S')
       time_label.config(text=current_time)
       root.after(1000, update_time)
    
    def main():
        interval = 1
        sent_prev, recv_prev = get_network_io()
        zerot = 0
        sentt = 0
        recvt = 0
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
    
    def start_main_thread():
        main_thread = Thread(target=main)
        main_thread.daemon = True 
        main_thread.start()

    root = tk.Tk()
    root.title("NoftiDocker")
    
    digital_font = font.Font(family='Digital-7', size=48)
    
    fixed_time = time.strftime('%H:%M:%S')
    fixed_time_label = tk.Label(root, text=fixed_time, font=digital_font)
    fixed_time_label.pack(pady=10)
    
    time_label = tk.Label(root, text="", font=digital_font, fg='blue')
    time_label.pack(pady=20)
    
    int1_label = tk.Label(root, text="0", font=digital_font, fg='black')
    int1_label.pack(pady=5)
    
    int2_label = tk.Label(root, text="0", font=digital_font, fg='black')
    int2_label.pack(pady=5)
    
    int3_label = tk.Label(root, text="0", font=digital_font, fg='green')
    int3_label.pack(pady=5)
    
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

def choose_folder(entry):
    folder = filedialog.askdirectory()
    entry.delete(0, tk.END)
    entry.insert(0, folder)
def print_fields(*entries):
    for entry in entries:
        print(entry.get())

root = tk.Tk()
root.title("App Window")
root.geometry("1280x1080")

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

fonts_list = ["Arial Black", "Bahnschrift Light", "Comic Sans MS", "Constantia", "Franklin Gothic Medium", "Ink Free", "Segoe Print", "Segoe Script","Gabriola", "Ink Free", "Segoe Print", "Segoe Script", "Alien Encounters"]


def update_font():
    choice = random.choice([0, 1])
    if choice == 0:
        for button in buttons:
            button.config(font=(random.choice(fonts_list), random.randint(25, 30)))
        root.after(1000, update_font)
    else:
        random_font = random.choice(fonts_list)
        for button in buttons:
            button.config(font=(random_font, random.randint(25, 30)))
        root.after(3000, update_font)
        
font_style = (random.choice(fonts_list), random.randint(25, 30))
button_width = 10
button_width_extend = 80
button_height = 2
button_pad_x = 5
button_pad_y = 5

label = tk.Label(main_frame, text="Saqlain has always been Nashty Boy.", font=font_style, fg="white", padx=20, pady=20)
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

button5 = tk.Button(main_frame, text="Check\nhash", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button5_clicked)
button6 = tk.Button(main_frame, text="Auto\nScroll", width=button_width, height=button_height, font=font_style, fg="white", padx=button_pad_x, pady=button_pad_y, command=button6_clicked)

button5.grid(row=2, column=0, padx=10, pady=10)
button6.grid(row=2, column=1, padx=10, pady=10)

buttons.extend([button5, button6])

label = tk.Label(main_frame, text="Is somebody gonna match his freak?", font=font_style, fg="white", padx=20, pady=20)
label.grid(row=3, column=0, columnspan=4, pady=(0, 10))
buttons.extend([label])

update_font()
update_all_button_colors()

root.mainloop()



