import secrets
import string
import hashlib
from getpass import getpass

USER_DETAILS_FILEPATH = "C:\Users.txt"

PUNCTUATIONS = "@#%!&$"

DEFAULT_PASSWORD_LENGTH = 14

INVALID_PASSWORD_MESSAGE = f'''
Password length must be a minimum of 14 characters.
Password must contain letter, number, and {PUNCTUATIONS}
Generating password with default length of {DEFAULT_PASSWORD_LENGTH} characters.'''

def password_generator(length = 14):
    characters = string.ascii_letters + string.digits + PUNCTUATIONS
    pwd = ''.join(secrets.choice(characters) for _ in range(length))
    return pwd

def password_hash(pwd):
    """Hash a password using SHA-256 algorithm"""
    pwd_bytes = pwd.encode('utf-8')
    hashed_pwd = hashlib.sha256(pwd_bytes).hexdigest()
    return hashed_pwd

def save_user(username, hashed_pwd):
    """Save user details to the users detail file"""
    with open(USER_DETAILS_FILEPATH, "a") as f:
        f.write(f"{username} {hashed_pwd}\n")

def user_exists(username):
    try:
        with open(USER_DETAILS_FILEPATH, "r") as f:
            for line in f:
                parts = line.split()
                if parts[0] == username:
                    return True
    except FileNotFoundError as fl_err:
        print(f"{fl_err.args[-1]}: {USER_DETAILS_FILEPATH}")
        print(f"System will create file: {USER_DETAILS_FILEPATH}")
    return False

def authenticate_user(username, password):
    with open(USER_DETAILS_FILEPATH, "r") as f:
        for line in f:
            parts = line.split()
            if parts [0] == username:
                hashed_password = parts[1]
                if hashed_password == password_hash(password):
                    return True
                else:
                    return False
    return False

def validate_input(password_length):
    try:
        password_length = int(password_length)
        if password_length < 14:
            raise ValueError("Password length must be at least 14 characters")
        return password_length
    except ValueError:
        print(INVALID_PASSWORD_MESSAGE)
        return DEFAULT_PASSWORD_LENGTH
    
def register():
    username = input("Enter Username: ")
    if user_exists(username):
        print("User already exists.")
        return
    length = input("Enter auto generated password length (Number 14 minimum): ")
    length = validate_input(length)
    password = password_generator(length)

    hashed_password = password_hash(password)
    save_user(username, hashed_password)
    print("User created successfully")
    print("Your password is:", password)

def login():
    username = input("Enter username: ")
    if not user_exists(username):
        print("User does not exist.")
        return
    
    password = getpass("Password: ")
    if not authenticate_user(username, password):
        print("Incorrect password.")
        return 
    
    print("Login successful.")

def main():
    while True:
        print("1.Regiser\n2.Login\n3.Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()    