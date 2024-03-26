import pyotp
import qrcode
import os
from encrypt_read_save_qrcode import KeyManager


# Save the qr code key temporary and then overwrite it when encrypting it.

secret_key_file_name = "Authentication_secret_key.txt"
secret_key_iv_file_name = "Authentication_secret_iv_key.txt"
Qr_Code_Path = "assets/images/qrcode/qrcode.png"


class TwoFactorAuthenticator:
    def __init__(self):
        self.key_manager = KeyManager()
        
    ### IS USER
    # IT CHECKS IF THE IV IS THERE BECAUSE THERE WILL NOT BE IV BY A NON REGISTERED USER
    # BUT THERE MAY BE A TEMP KEY 
    def is_authorized_2fa(self):
        return os.path.isfile(secret_key_iv_file_name)
    
    def write_temp_key(self,key):
        with open(secret_key_file_name,'w') as file:
            file.write(key)
            
    def read_temp_key(self):
        with open(secret_key_file_name,'r') as file:
            data = file.read()
        return data
    
    ###REGISTER

    def generate_new_qr_code(self):
        # Function to generate a secret key for a user
        def generate_secret_key():
            return pyotp.random_base32()

        secret_key = generate_secret_key()
        self.write_temp_key(secret_key)
        otp_uri = pyotp.totp.TOTP(secret_key).provisioning_uri("SurPass", issuer_name="SURPASS Password Manager")
        qr_image = qrcode.make(otp_uri)
        data = f"Key:{secret_key}, username:SurPass ,issuer_name:SURPASS Password Manager"
        qr_image.save(Qr_Code_Path)
        return qr_image,data

    def verify_new_otp(self, user_otp):
        totp = pyotp.TOTP(self.read_temp_key())
        return totp.verify(user_otp)
    # Used when registiring
    # Save the otp and delete the qr code
    def save_otp(self, user_input_otp):
        if self.verify_new_otp(user_input_otp):
            self.key_manager.write_key_and_iv(self.read_temp_key())
            if os.path.exists(Qr_Code_Path):
                # Delete the file
                os.remove(Qr_Code_Path)
                print("File deleted successfully.")
            return "KEY SAVED"
            
    ####LOGIN
    # USED BY THE APP    
    # Function to verify OTP entered by the user after LOGIN

    def verify_otp(self, user_otp):
        key = self.key_manager.read_key()
        totp = pyotp.TOTP(key)
        return totp.verify(user_otp)