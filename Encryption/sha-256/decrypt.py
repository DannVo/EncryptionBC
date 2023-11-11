import base64
import hashlib
import tkinter as tk
from cryptography.fernet import Fernet

def generate_key():
    password = password_entry.get()

    # Convert the password string to bytes
    password_bytes = password.encode('utf-8')

    # Generate the SHA256 hash of the password
    sha256_hash = hashlib.sha256(password_bytes)

    # Get the hexadecimal representation of the hash
    key = sha256_hash.digest()

    # Base64 encode the key
    encoded_key = base64.urlsafe_b64encode(key)

    return encoded_key

def decrypt_message():
    encrypted_message = encrypted_message_entry.get("1.0", tk.END).strip()

    # Generate the key
    key = generate_key()

    # Create a Fernet encryption object with the key
    cipher_suite = Fernet(key)

    # Decrypt the message
    decrypted_message = cipher_suite.decrypt(encrypted_message.encode('utf-8'))

    # Update the decrypted message label
    decrypted_message_value_label.config(text=decrypted_message.decode('utf-8'))

# Create the main window
window = tk.Tk()
window.title("Receiver")

# Set the window size and position it in the middle of the screen
window_width = 400
window_height = 400  # Increase the height to accommodate the longer textbox
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
window.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Set the background color of the window
window.configure(bg='#f2f2f2')

# Create a header label
header_label = tk.Label(window, text="Decryption", bg='#f2f2f2', fg='#333333', font=('Arial', 18, 'bold'))
header_label.pack(pady=10)

# Create a label and an entry for the password
password_label = tk.Label(window, text="Password:", bg='#f2f2f2', fg='#333333', font=('Arial', 14, 'bold'))
password_label.pack()
password_entry = tk.Entry(window, show="*", bg='#ffffff', fg='#333333', font=('Arial', 14))
password_entry.pack()

# Create a label and a textbox for the encrypted message
encrypted_message_label = tk.Label(window, text="Encrypted Message:", bg='#f2f2f2', fg='#333333', font=('Arial', 14, 'bold'))
encrypted_message_label.pack()
encrypted_message_entry = tk.Text(window, height=4, width=20, bg='#ffffff', fg='#333333', font=('Arial', 14))
encrypted_message_entry.pack()

# Create a button to decrypt the message
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_message, bg='#4caf50', fg='#ffffff', font=('Arial', 14, 'bold'))
decrypt_button.pack(pady=10)

# Create a label to display the decrypted message
decrypted_message_label = tk.Label(window, text="Decrypted Message: ", bg='#f2f2f2', fg='#333333', font=('Arial', 14, 'bold'))
decrypted_message_label.pack()
# Create a label to display the decrypted message value
decrypted_message_value_label = tk.Label(window, text="", bg='#f2f2f2', fg='orange', font=('Arial', 14))
decrypted_message_value_label.pack()

# Start the GUI event loop
window.mainloop()
