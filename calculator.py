import tkinter as tk
import random

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
