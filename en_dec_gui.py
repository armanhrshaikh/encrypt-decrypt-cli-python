import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption/Decryption")
        self.root.geometry("500x400")

        self.option_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.input_file_var = tk.StringVar()
        self.output_file_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Option screen
        option_frame = tk.Frame(self.root)
        option_frame.pack()

        encrypt_radio = tk.Radiobutton(option_frame, text="Encrypt", variable=self.option_var, value='encrypt')
        decrypt_radio = tk.Radiobutton(option_frame, text="Decrypt", variable=self.option_var, value='decrypt')
        encrypt_radio.pack(side=tk.LEFT, padx=10)
        decrypt_radio.pack(side=tk.LEFT, padx=10)

        # Password screen
        password_frame = tk.Frame(self.root)
        password_frame.pack()

        password_label = tk.Label(password_frame, text="Enter password:")
        password_entry = tk.Entry(password_frame, show='*', textvariable=self.password_var)
        password_label.pack(pady=10)
        password_entry.pack(pady=10)

        # File selection screen
        file_frame = tk.Frame(self.root)
        file_frame.pack()

        input_file_label = tk.Label(file_frame, text="Select input file:")
        input_file_entry = tk.Entry(file_frame, textvariable=self.input_file_var)
        input_file_button = tk.Button(file_frame, text="Browse", command=self.choose_input_file)
        output_file_label = tk.Label(file_frame, text="Select output file:")
        output_file_entry = tk.Entry(file_frame, textvariable=self.output_file_var)
        output_file_button = tk.Button(file_frame, text="Browse", command=self.choose_output_file)

        input_file_label.grid(row=0, column=0, pady=10)
        input_file_entry.grid(row=0, column=1, pady=10)
        input_file_button.grid(row=0, column=2, pady=10)
        output_file_label.grid(row=1, column=0, pady=10)
        output_file_entry.grid(row=1, column=1, pady=10)
        output_file_button.grid(row=1, column=2, pady=10)

        # Encrypt/Decrypt button
        process_button = tk.Button(self.root, text="Encrypt/Decrypt", command=self.process)
        process_button.pack(pady=20)

        # Result label
        self.result_label = tk.Label(self.root, text="")
        self.result_label.pack()

    def choose_input_file(self):
        file_path = filedialog.askopenfilename()
        self.input_file_var.set(file_path)

    def choose_output_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".enc" if self.option_var.get() == "encrypt" else ".txt")
        self.output_file_var.set(file_path)

    def process(self):
        option = self.option_var.get()
        password = self.password_var.get()
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()

        if not password or not input_file or not output_file:
            self.result_label.config(text="Please fill in all fields.")
            return

        if option == 'encrypt':
            key = self.generate_key(password)
            self.save_key(key, 'secret.key')
            self.encrypt_file(key, input_file, output_file)
            self.result_label.config(text="File '{}' encrypted to '{}'.".format(input_file, output_file))
        elif option == 'decrypt':
            password_verify = self.password_verify_dialog()
            if not password_verify:
                return
            key = self.load_key('secret.key', password_verify)
            self.decrypt_file(key, input_file, output_file)
            self.result_label.config(text="File '{}' decrypted to '{}'.".format(input_file, output_file))

    def password_verify_dialog(self):
        password_verify_var = tk.StringVar()
        password_verify_window = tk.Toplevel(self.root)
        password_verify_window.title("Password Verification")

        label = tk.Label(password_verify_window, text="Enter password to decrypt:")
        entry = tk.Entry(password_verify_window, show='*', textvariable=password_verify_var)
        button = tk.Button(password_verify_window, text="Verify", command=password_verify_window.destroy)

        label.pack(pady=10)
        entry.pack(pady=10)
        button.pack(pady=10)

        password_verify_window.wait_window()

        return password_verify_var.get()

    @staticmethod
    def generate_key(password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=b'salt_salt',
            iterations=100000,
            length=32,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def save_key(key, filename):
        with open(filename, 'wb') as key_file:
            key_file.write(key)

    @staticmethod
    def load_key(filename, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=b'salt_salt',
            iterations=100000,
            length=32,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_file(key, input_file, output_file):
        cipher = Fernet(key)
        with open(input_file, 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

    @staticmethod
    def decrypt_file(key, input_file, output_file):
        cipher = Fernet(key)
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
