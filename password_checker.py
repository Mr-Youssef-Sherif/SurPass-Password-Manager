def check_password(password):
    #print(" RULES\nCheckpoint(1) Length must be between 10 and 18.\nCheckpoint(2) Must contain lowercase letters.\nCheckpoint(3) Must contain uppercase letters.\nCheckpoint(4) Must contain numbers.\nCheckpoint(5) Must contain special characters.")
    length_passed = 12 <= len(password)
    lowercase_passed = any(char.islower() for char in password)
    uppercase_passed = any(char.isupper() for char in password)
    numbers_passed = any(char.isdigit() for char in password)
    special_passed = any(char in '!@~#$%^&*()_+=/?' for char in password)

    #if length_passed:
    #    print("Checkpoint(1) PASSED✅")
    #else:
    #    print("Checkpoint(1) FAILED, Password must be between 10 and 18 characters❌")
    #if lowercase_passed:
    #    print("Checkpoint(2) PASSED✅")
    #else:
    #    print("Checkpoint(2) FAILED, Password must contain lowercase letters❌")
    #if uppercase_passed:
    #    print("Checkpoint(3) PASSED✅")
    #else:
    #    print("Checkpoint(3) FAILED, Password must contain uppercase letters❌")
    #if numbers_passed:
    #    print("Checkpoint(4) PASSED✅")
    #else:
    #    print("Checkpoint(4) FAILED, Password must contain numbers❌")
    #if special_passed:
    #    print("Checkpoint(5) PASSED✅")
    #else:
    #    print("Checkpoint(5) FAILED, Password must contain special characters❌")
    #    
    #if all([length_passed, lowercase_passed, uppercase_passed, numbers_passed, special_passed]):
    #    print("Congratulations! Your password is eligible to be used✅")
    #else:
    #    print("Sorry! Your password is not eligible to be used❌")
        
    return length_passed,lowercase_passed,uppercase_passed,numbers_passed,special_passed



# Testing
#def main():
#    start = input("Do you want to check your password? (Y/N): ")
#    if start.upper() == 'Y':
#        pass_to_check = str(input("Enter a test pasword: "))
#        check_password(pass_to_check)
#        length_passed,lowercase_passed,uppercase_passed,numbers_passed,special_passed = check_password(pass_to_check)
#    else:
#        print("Exiting...")
#
#if __name__ == "__main__":
#    main()