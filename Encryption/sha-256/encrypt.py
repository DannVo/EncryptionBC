import base64
import hashlib
import tkinter as tk
import pyperclip
from cryptography.fernet import Fernet

def generate_key():
    password = password_entry.get()

    # Convert the password string to bytes
    password_bytes = password.encode('utf-8')

    # Generate the SHA256 hash of the password
    sha256_hash = hashlib.sha256(password_bytes)

    # Get the hexadecimal representation of the hash
    key = sha256_hash.digest()

    # Encode the key using base64 and ensure it is URL-safe
    key = base64.urlsafe_b64encode(key)

    # Pad the key if it is less than 32 bytes
    key = key.ljust(32, b'=')

    return key

def encrypt_message():
    message = message_entry.get()

    # Generate the key
    key = generate_key()

    # Create a Fernet encryption object with the key
    cipher_suite = Fernet(key)

    # Encrypt the message
    encrypted_message = cipher_suite.encrypt(message.encode('utf-8'))

    # Update the encrypted message label
    encrypted_message_label.config(text="Encrypted Message: " + encrypted_message.decode('utf-8'))

    # Copy the encrypted message to the clipboard
    pyperclip.copy(encrypted_message.decode('utf-8'))

    # Send success message
    send_success_label.config(text="Message Sent Successfully!")

# Create the main window
window = tk.Tk()
window.title("Encryption")

# Set the window size and position it in the middle of the screen
window_width = 400
window_height = 300
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
window.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Set the background color of the window
window.configure(bg='#FFEBCD')  # Light Orange

# Create a form frame with padding
form_frame = tk.Frame(window, bg='#FFEBCD', padx=10, pady=10)  # Light Orange
form_frame.pack()

# Create a header label
header_label = tk.Label(form_frame, text="Encryption", bg='#FFEBCD', fg='black', font=('Arial', 18, 'bold'))  # Light Orange
header_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Create a label and an entry for the password
password_label = tk.Label(form_frame, text="Password:", bg='#FFEBCD', fg='black', font=('Arial', 14, 'bold'))  # Light Orange
password_label.grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(form_frame, show="*", bg='white', fg='black', font=('Arial', 14))
password_entry.grid(row=1, column=1, padx=10, pady=10)

# Create a label and an entry for the message
message_label = tk.Label(form_frame, text="Message:", bg='#FFEBCD', fg='black', font=('Arial', 14, 'bold'))  # Light Orange
message_label.grid(row=2, column=0, padx=10, pady=10)
message_entry = tk.Entry(form_frame, bg='white', fg='black', font=('Arial', 14))
message_entry.grid(row=2, column=1, padx=10, pady=10)

# Create a button to encrypt the message
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_message, bg='#4caf50', fg='white', font=('Arial', 14, 'bold'))
encrypt_button.pack(pady=10)

# Create a label to display the encrypted message
encrypted_message_label = tk.Label(window, text="Encrypted Message: ", bg='#FFEBCD', fg='black', font=('Arial', 14, 'bold'))  # Light Orange
encrypted_message_label.pack()

# Create a button to copy the encrypted message
copy_button = tk.Button(window, text="Copy", command=lambda: pyperclip.copy(encrypted_message_label.cget("text")[19:]), bg='#2196f3', fg='white', font=('Arial', 14, 'bold'))
copy_button.pack(pady=10)

# Create a label to display the send success message
send_success_label = tk.Label(window, text="", bg='#FFEBCD', fg='black', font=('Arial', 14, 'bold'))  # Light Orange
send_success_label.pack()

# Start the GUI event loop
window.mainloop()
