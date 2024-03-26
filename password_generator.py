import random
import password_checker
import string

# Define character lists
lst1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
lst2 = 'abcdefghijklmnopqrstuvwxyz'
lst3 = '!@#$%^&*()_+-/!?'
lst4 = '123456789123456789'

# Function to generate password
def generate_password(length, upper_case=False, include_numbers=False, include_symbols=False):
    characters = lst1
    if upper_case:
        characters += lst2
    if include_numbers:
        characters += lst4
    if include_symbols:
        characters += lst3
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def generate_strong_password(length):
    while True:
        characters = list(string.ascii_lowercase)  # Lowercase letters are always included

        characters += list(string.ascii_uppercase)

        characters += list(string.digits)

        characters += list(string.punctuation)
        
        password = ''.join(random.choice(characters) for _ in range(length))
        
        # Check if the password meets the criteria
        length_passed, lowercase_passed, uppercase_passed, numbers_passed, special_passed = password_checker.check_password(password)
        
        if length_passed and lowercase_passed and uppercase_passed and numbers_passed and special_passed:  
            return password

# Testing

# Main function
#def main():
#    start = input("Do you want to generate a password? (Y/N): ")
#    if start.upper() == 'Y':
#        upper_case = input("Do you want your password to be in uppercase? (Y/N): ").upper() == 'Y'
#        include_numbers = input("Do you want numbers in your password? (Y/N): ").upper() == 'Y'
#        include_symbols = input("Do you want symbols in your password? (Y/N): ").upper() == 'Y'
#        length = int(input("Enter your preferred password length (10 to 18): "))
#        if 10 <= length <= 18:
#            password = generate_password(length, upper_case, include_numbers, include_symbols)
#            print("Your Password is:", password)
#        else:
#            print("Invalid length. Password length should be between 10 and 18.")
#    else:
#        print("Exiting...")
        
# main()