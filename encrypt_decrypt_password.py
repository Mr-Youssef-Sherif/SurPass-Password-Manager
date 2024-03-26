import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

class EncryptionAndDecryptionManager:
    def __init__(self,salt, hashed_master_password):
        self.salt = salt
        self.hashed_master_password = bytes.fromhex(hashed_master_password)

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Output key length in bytes (256 bits for AES-256).
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.hashed_master_password)  # This is the AES encryption key.
        return key

    def encrypt_data(self, data_to_encrypt):
        encryption_key = self.derive_key()
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_to_encrypt) + padder.finalize()

        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ct

    def decrypt_data(self, iv, ciphertext):
        encryption_key = self.derive_key()

        decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend()).decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')

