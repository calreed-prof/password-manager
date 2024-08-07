import os
import sqlite3
import hashlib
import getpass
import bcrypt
from cryptography.fernet import Fernet
import base64

# This is going to be the connection setup for the database
conn = sqlite3.connect("password_manager.db")
c = conn.cursor()

# This just clears the terminal
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

c.execute('''CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          username TEXT NOT NULL,
          mstpassword TEXT NOT NULL
          )''')

c.execute('''Create TABLE IF NOT EXISTS passwords (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          userid INTEGER NOT NULL,
          website TEXT NOT NULL,
          username TEXT NOT NULL,
          password TEXT NOT NULL,
          FOREIGN KEY (userid) REFERENCES users(id)
          )''')
conn.commit()

# This will hash the password using bcrypt
def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

# bcrypt has a nice feature where it can automically check the password for us
def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from the password using PBKDF2."""
    kdf = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm
        password.encode(),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations of SHA-256
    )
    return base64.urlsafe_b64encode(kdf)

# This will encrypt the password using Fernet
def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())

# This will decrypt the password using Fernet
def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

#Starting Menu
def login_menu():
    create_or_signin = input(f"Welcome to your password manager!\nPlease press 1 to signin, or 2 to create an account: ")
    if create_or_signin == "1":
        signin()
    elif create_or_signin == "2":
        create_account()
    else:
        print("Invalid input")
        clear_screen()
        login_menu()

def view_passwords(userid):
    c.execute("SELECT * FROM passwords WHERE userid = ?", (userid))
    results = c.fetchall()
    for row in results:
        print(row)

def add_password(userid, key):
    website = input("Please enter the website: ")
    username = input("Please enter the username: ")
    password = input("Please enter the password: ")
    
    # Encrypt the password
    encrypted_password = encrypt_password(password, key)
    
    c.execute("INSERT INTO passwords (userid, website, username, password, salt) VALUES (?, ?, ?, ?, ?)", (userid, website, username, encrypted_password))
    conn.commit()
    print("Password has been added successfully! Press enter to continue...")
    input()



def main_menu(userid, derived_key):
    clear_screen()
    option = input(f"Please select an option\n1. View Saved Passwords\n2. Add Password\n3. Delete Saved Password\n4. Update Saved Password")
    if option == "1":
        view_passwords(userid)
    elif option == "2":
        add_password(userid, derived_key)
    elif option == "3":
        delete_password(userid)
    elif option == "4":
        update_password(userid)
    else:
        print("Invalid input")
        clear_screen()
        main_menu(userid)

def signin():
    # Signin Menu
    clear_screen()
    print("Welcome Back! (Enter 1 to return to the main menu): ")
    username = input("Please enter your username: ")
    if username == 1:
        login_menu()
    else:
        pass
    password = input("Please enter your password: ")
    hashed_pass_key = hash_password(password)

    # This will be placed in a try command to stop errors from crashing program
    try:
        c.execute("SELECT id, mstpassword FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result and hashed_pass_key == result[1]:
            salt = os.urandom(16)
            derived_key = derive_key(password, salt)
            print("Welcome Back! Press enter to continue...")
            input()
            main_menu(result[0], derived_key)
        else:
            print("Incorrect password or username, please try again...")
            input()
            signin()
    except:
        print("Incorrect password or username, please try again...")
        input()
        signin()

def create_account():
    # Create Account Menu
    clear_screen()
    username = input("Please enter username: ")
    if username == c.execute("SELECT username FROM users"):
        print("Username already taken, please try again")
        input()
        create_account()
    else:
        mstpassword = input("Please enter password: ")
        hashed_mst_passkey = hash_password(mstpassword)
        c.execute(f"INSERT INTO users (username, mstpassword) VALUES (?, ?)", (username, hashed_mst_passkey))
        conn.commit()
        print("Your Account has been Successfully Created! Press enter to continue...")
        input()
        signin()

login_menu()
