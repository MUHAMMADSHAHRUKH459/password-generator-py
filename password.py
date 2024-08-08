import tkinter as tk
from tkinter import messagebox
import secrets
import string

# Function to generate a secure password
def generate_password():
    length = int(length_var.get())
    include_uppercase = uppercase_var.get()
    include_numbers = numbers_var.get()
    include_symbols = symbols_var.get()

    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation

    password = ''.join(secrets.choice(characters) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    footer_label.config(text="Your password is ready")

# Function to copy the generated password to the clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Password Generator", "Password copied to clipboard!")

# Setting up the main application window
root = tk.Tk()
root.title("Secure Password Generator")
root.geometry("400x300")  # Adjusted window size
root.configure(bg="#1E1E1E")  # Background color

# Font settings
font_large = ("Helvetica", 14, "bold")
font_medium = ("Helvetica", 12)
font_header = ("Helvetica", 18, "bold")
font_footer = ("Helvetica", 12, "italic")
font_entry_large = ("Helvetica", 16, "bold")  # Larger and bold font for length entry
font_password = ("Helvetica", 16, "bold")  # Larger and bold font for password entry

# Create a frame for centering content
frame = tk.Frame(root, bg="#1E1E1E")
frame.pack(expand=True, fill='both')

# Header Label
tk.Label(frame, text="PASSWORD GENERATOR", font=font_header, fg="#fee440", bg="#1E1E1E").pack(pady=10)

# Password length input
tk.Label(frame, text="Password Length:", font=font_large, fg="#FFFFFF", bg="#1E1E1E").pack(pady=10)
length_var = tk.StringVar(value="12")
length_entry = tk.Entry(frame, textvariable=length_var, width=5, font=font_entry_large)  # Updated font settings
length_entry.pack(pady=5)

# Checkbox options
uppercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

tk.Checkbutton(frame, text="Include Uppercase Letters", variable=uppercase_var, font=font_medium, fg="#FFFFFF", bg="#1E1E1E", selectcolor="#3A3A3A").pack(pady=5)
tk.Checkbutton(frame, text="Include Numbers", variable=numbers_var, font=font_medium, fg="#FFFFFF", bg="#1E1E1E", selectcolor="#3A3A3A").pack(pady=5)
tk.Checkbutton(frame, text="Include Symbols", variable=symbols_var, font=font_medium, fg="#FFFFFF", bg="#1E1E1E", selectcolor="#3A3A3A").pack(pady=5)

# Button styles
btn_style = {"font": font_large, "bg": "#4CAF50", "fg": "white", "activebackground": "#45A049", "bd": 0, "highlightthickness": 0, "width": 20}

# Button to generate password
tk.Button(frame, text="Generate Password", command=generate_password, **btn_style).pack(pady=15)

# Entry to display the generated password
password_entry = tk.Entry(frame, width=30, font=font_password, bg="#2E2E2E", fg="#FFFFFF", bd=0, highlightthickness=0, insertbackground="white")
password_entry.pack(pady=10)

# Button to copy the password to clipboard
tk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard, **btn_style).pack(pady=5)

# Footer Label
footer_label = tk.Label(frame, text="", font=font_footer, fg="#fee440", bg="#1E1E1E")
footer_label.pack(side=tk.BOTTOM, pady=10)

# Run the application
root.mainloop()

