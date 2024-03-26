import hashlib
import os
import base64
from crud_credentials import UserCredentials
from map import Map
from encrypt_decrypt_password import EncryptionAndDecryptionManager

#pip install cryptography
# Authenticat the user if there is no user create a new one
# CRUD to the credentials database made with sqflite
# Make the user able to view the saved passwords if authorized
# make screen time for the password manager
# Safety procedures max tries is 3 times before cool down

IS_AUTHORIZED = False
TRY_COUNT = 0
MASTER_PASS_FILE_NAME = 'masterPassword.hash'
USERNAME_FILE_NAME = "username.hash"
SALT_FILE_NAME = "Salt"
NEW_MASTER_VALUE = None
IS_MASTER_PASS_SET = False
table = UserCredentials()


########### MASTER PASSWORD ############ 

# Check if there is a current user
def check_user():
    hash_value = read_hashed_master_from_file()
    if hash_value:
        return True
    else:
        return False
    
# MASTER PASSWORD HANDLING

def master_password_validator(username,master_key):
    global TRY_COUNT   
    
    # Read the saved master key hash value
    master_key_hash_value = read_hashed_master_from_file()

    # Read the saved username hash value
    username_hash_value = read_hashed_username_from_file()

    # Hash the user's username using SHA-256
    hashed_username_input = hashlib.sha256(username.encode()).hexdigest()

    # Hash the user's master_key using SHA-256
    hashed_master_key_input = hashlib.sha256(master_key.encode()).hexdigest()
    
    # Check try count
    if TRY_COUNT < 3:

        # Compare the user's hashed input with the stored master hash
        if (master_key_hash_value == hashed_master_key_input) and (username_hash_value == hashed_username_input):
            print("Correct username and password")
            return True
        else:
            TRY_COUNT += 1
            print("Incorrect password. Please try again.")
    else:
        print("You ran out of attempts ")
 


       
def set_a_master_password(username,master_key):
    global IS_MASTER_PASS_SET
    
    while not IS_MASTER_PASS_SET:
        try:
            # Generate a salt. This should be saved along with your encrypted data to use during decryption.
            salt = os.urandom(16)
            # Save the hash
            save_hashed_master_to_file(master_key)
            # Save the hash
            save_hashed_username_to_file(username)
            # Save the salt
            save_salt_to_file(salt)
            print("User created")
            IS_MASTER_PASS_SET = True
            return True
        except KeyboardInterrupt:
            print("\nOperation interrupted by the user. Exiting...")
            exit()
        except Exception as e:
            print("An error occurred:", e)
            print("Please try again.")
            

# Create

def save_hashed_master_to_file(master_key):
    """Saves the hash value to a file."""
    with open(MASTER_PASS_FILE_NAME, 'w') as file:
        hash = hashlib.sha256(master_key.encode()).hexdigest()
        file.write(hash)
        
def save_hashed_username_to_file(username):
    """Saves the hash value to a file."""
    with open(USERNAME_FILE_NAME, 'w') as file:
        hash = hashlib.sha256(username.encode()).hexdigest()
        file.write(hash)

# Read

# It will check if there is a hash master value wich indicates that there is a user and password
def read_hashed_master_from_file():
    # Reads the hash value from a file.
    try:
        with open(MASTER_PASS_FILE_NAME, 'r') as file:
            hash_value = file.read().strip()
            if hash_value:
                return hash_value
            else:
                return False
    except FileNotFoundError:
        # File not found
        return False
    
def read_hashed_username_from_file():
    # Reads the hash value from a file.
    try:
        with open(USERNAME_FILE_NAME, 'r') as file:
            hash_value = file.read().strip()
            if hash_value:
                return hash_value
            else:
                return False
    except FileNotFoundError:
        # File not found
        return False

#-----------------------------------------------------------------------------------------------#
    

# Create

def save_salt_to_file(salt):
    """Saves the salt value to a file."""
    salt_encoded = base64.b64encode(salt).decode()  # Encode the salt as base64 and decode to string
    with open(SALT_FILE_NAME, 'w') as file:
        file.write(salt_encoded)  # Writing the encoded salt string

# Read

# It will check if there is a salt master value 
def read_salt_from_file():
    try: 
        """Reads the salt value from a file."""
        with open(SALT_FILE_NAME, 'r') as file:
            salt_encoded = file.read().strip()  # Read the encoded salt string
        salt = base64.b64decode(salt_encoded.encode())  # Decode the base64 string to binary
        return salt
    except FileNotFoundError:
        # File not found
        return False

########### PASSWORDS ############   

# Handle the password and their corresponding usernames



# Create
    
def add_item(password_value, username_value='', website_name='', note_value='',url_value=''):
    # Get data
    # Encrypt pasword
    salt = read_salt_from_file()
    hashed_master_key = read_hashed_master_from_file()

    encryption_manager = EncryptionAndDecryptionManager(salt=salt,hashed_master_password=hashed_master_key)
    
    iv, ciphertext = encryption_manager.encrypt_data(password_value.encode())
    #Save items
    table.insert_data(iv, ciphertext, username=username_value, website_name=website_name,note= note_value,url= url_value)
    print("item added")

# Read
# It will return a list of lists
# each list will have website_name,username,password,url,note
def read_user_credentials():
    rows = table.get_all_data()
    mapped_data = [Map(*row) for row in rows]
    return mapped_data
    
# Update

def update_item(id,new_iv_value, new_password_value, new_username_value, new_website_name, new_note_value, new_url_value):
    table.update_data(id,new_iv_value, new_password_value, new_username_value, new_website_name, new_note_value, new_url_value)
    print("item updated")


# Delete
def delete_item(id):
    table.delete_data(id)
    print("item deleted")

## Testing

#if __name__ == '__main__':
#    rows = table.get_all_data()
#    mapped_data = [Map(*row) for row in rows]
#    print(mapped_data)
#    for data in mapped_data:
#        print(data)
#        ciphertext = data.password
#        username = data.username
#        iv = data.iv
#        print(ciphertext)
#        decrypted_text = encryption_manager.decrypt_data(iv, ciphertext)
#        print(f"Username:{username}")
#        print(f"Password:{decrypted_text}")