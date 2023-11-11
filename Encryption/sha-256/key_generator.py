import hashlib
import tkinter as tk
import pyperclip

def generate_key():
    password = password_entry.get()

    # Convert the password string to bytes
    password_bytes = password.encode('utf-8')

    # Generate the SHA256 hash of the password
    sha256_hash = hashlib.sha256(password_bytes)

    # Get the hexadecimal representation of the hash
    key = sha256_hash.hexdigest()

    # Update the key label
    key_label.config(text="Generated Key: " + key)

    return key

def copy_key():
    key = generate_key()

    # Copy the key to the clipboard
    pyperclip.copy(key)

# Create the main window
window = tk.Tk()
window.title("Key Generator")

# Set the background color of the window
window.configure(bg='#f2f2f2')

# Create a header label
header_label = tk.Label(window, text="Key Generator", bg='#f2f2f2', fg='#333333', font=('Arial', 18, 'bold'))
header_label.pack(pady=20)

# Create a label and an entry for the password
password_label = tk.Label(window, text="Password:", bg='#f2f2f2', fg='#333333', font=('Arial', 14))
password_label.pack()
password_entry = tk.Entry(window, show="*", bg='white', fg='#333333', font=('Arial', 14))
password_entry.pack()

# Create a button to generate the key
generate_button = tk.Button(window, text="Generate Key", command=generate_key, bg='#4caf50', fg='#ffffff', font=('Arial', 14, 'bold'))
generate_button.pack(pady=10)

# Create a label to display the generated key
key_label = tk.Label(window, text="Generated Key: ", bg='#f2f2f2', fg='#333333', font=('Arial', 14))
key_label.pack()

# Create a button to copy the key
copy_button = tk.Button(window, text="Copy Key", command=copy_key, bg='#2196f3', fg='#ffffff', font=('Arial', 14, 'bold'))
copy_button.pack(pady=10)

# Start the GUI event loop
window.mainloop()
