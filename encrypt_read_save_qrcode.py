import base64
import os
from encrypt_decrypt_password import EncryptionAndDecryptionManager
import main

class KeyManager:
    def __init__(self):
        self.secret_key_file_name = "Authentication_secret_key.txt"
        self.secret_key_iv_file_name = "Authentication_secret_iv_key.txt"
        self.encrpt_decrypt_object = None
        self.hashed_master = main.read_hashed_master_from_file()
        self.salt = main.read_salt_from_file()
        self.initialize_encryption()

    def initialize_encryption(self):
        self.encrpt_decrypt_object = EncryptionAndDecryptionManager(hashed_master_password=self.hashed_master, salt=self.salt)

    def write_file(self, filename, data):
        if isinstance(data, bytes):  # Check if data is binary
            encoded_data = base64.b64encode(data).decode('utf-8')  # Encode to Base64
        else:
            encoded_data = data  # No encoding needed if already a string

        with open(filename, 'w') as file:  # Open in text write mode
            file.write(encoded_data)  # Write the encoded data (string)

    def read_file(self, filename):
        try:
            with open(filename, 'r') as file:
                return file.read()
        except FileNotFoundError:
            # Handle the case where the file is not found
            raise FileNotFoundError(f"The file '{filename}' is missing. Please ensure it exists.")
        except Exception as e:
            # Handle other exceptions gracefully
            raise e        

    def encrypt_secret_key(self, plain_data):
        iv, ct = self.encrpt_decrypt_object.encrypt_data(data_to_encrypt=plain_data)
        return iv, ct

    def decrypt_secret_key(self, iv, ciphered_data):
        plain_data = self.encrpt_decrypt_object.decrypt_data(iv=iv, ciphertext=ciphered_data)
        return plain_data

    def write_key_and_iv(self, secret_key):
        # Encrypt the secret key and save it
        iv, ct = self.encrypt_secret_key(secret_key.encode())
        encoded_data = base64.b64encode(ct).decode('utf-8')
        self.write_file(self.secret_key_file_name, encoded_data)
        self.write_file(self.secret_key_iv_file_name, iv)

    def read_key(self):
        # Read IV from file
        iv_bytes = self.read_file(self.secret_key_iv_file_name)
        # Decode IV from Base64
        iv = base64.b64decode(iv_bytes)

        # Read encrypted key from file
        ct = self.read_file(self.secret_key_file_name)
        # Decode encrypted key from Base64
        ct_bytes = base64.b64decode(ct)

        # Decrypt the secret key to authenticate
        key = self.decrypt_secret_key(iv, ct_bytes)
        return key
    
    def read_temp_key(self):
        # Read encrypted key from file
        temp_key = self.read_file(self.secret_key_file_name)
        return temp_key