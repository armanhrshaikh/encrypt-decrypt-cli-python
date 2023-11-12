from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_key(password):
    # Derive a key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'salt_salt',
        iterations=100000,
        length=32,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename, password):
    # Derive the key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'salt_salt',
        iterations=100000,
        length=32,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(key, input_file, output_file):
    cipher = Fernet(key)
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(key, input_file, output_file):
    cipher = Fernet(key)
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Take user input for file names and operation
option = input("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter 1 or 2: ")

if option not in ['1', '2']:
    print("Invalid option. Please enter 1 or 2.")
    exit()

password = input("Enter password: ")

input_file = input("Enter the name of the file: ")
output_file = input("Enter the name of the {}ed file: ".format("encrypt" if option == '1' else "decrypt"))

# Example usage:
if option == '1':
    key = generate_key(password)
    save_key(key, 'secret.key')
    encrypt_file(key, input_file, output_file)
    print("File '{}' encrypted to '{}'.".format(input_file, output_file))
elif option == '2':
    password_verify = input("Enter password to decrypt: ")
    key = load_key('secret.key', password_verify)
    decrypt_file(key, input_file, output_file)
    print("File '{}' decrypted to '{}'.".format(input_file, output_file))
