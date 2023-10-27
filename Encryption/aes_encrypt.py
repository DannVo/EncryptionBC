# AES Encryption Example
from cryptography.fernet import Fernet

# Generate a new AES key
key = Fernet.generate_key()

# Create a Fernet cipher instance with the key
cipher = Fernet(key)

# Encrypt a message
message = b"Check Algorithm, AES encryption!"
encrypted_message = cipher.encrypt(message)

# Decrypt the message
decrypted_message = cipher.decrypt(encrypted_message)

print("Original Message:", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)
