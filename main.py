import os
import sqlite3
import hashlib
import getpass
import bcrypt
from cryptography.fernet import Fernet
import base64
from tabulate import tabulate
import time

# This is going to be the connection setup for the database
conn = sqlite3.connect("password_manager.db")
c = conn.cursor()

# This just clears the terminal
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

c.execute('''CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          username TEXT NOT NULL,
          mstpassword TEXT NOT NULL,
          salt TEXT NOT NULL
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
    clear_screen()
    create_or_signin = input(f"Welcome to your password manager!\nPlease press 1 to signin, or 2 to create an account: ")
    if create_or_signin == "1":
        signin()
    elif create_or_signin == "2":
        create_account()
    else:
        print("Invalid input")
        clear_screen()
        login_menu()

def view_passwords(userid, key, mstpassword):
    c.execute("SELECT website, username, password FROM passwords WHERE userid = ?", (userid,))
    results = c.fetchall()

    decrypted_data = []
    for row in results:
        website, username, password = row
        decrypted_password = decrypt_password(password, key)
        decrypted_data.append([website, username, decrypted_password])

    headers = ["Website", "Username", "Password"]

    if decrypted_data == []:
        input("No Passwords Saved! Add one First")
        main_menu()
    else:
        print(tabulate(decrypted_data, headers=headers, tablefmt="grid"))
        input("Press Enter when ready to continue...")
        main_menu(userid, mstpassword)

def add_password(userid, key, mstpassword):
    clear_screen()
    print("ADD A PASSWORD")
    website = input("Please enter the website: ")
    username = input("Please enter the username: ")
    password = input("Please enter the password: ")
    
    # Encrypt the password
    encrypted_password = encrypt_password(password, key)
    
    c.execute("INSERT INTO passwords (userid, website, username, password) VALUES (?, ?, ?, ?)", (userid, website, username, encrypted_password))
    conn.commit()
    print("Password has been added successfully! Press enter to continue...")
    input()
    main_menu(userid, mstpassword)

def delete_password(userid, key, mstpassword):
    c.execute("SELECT id, website, username, password FROM passwords WHERE userid = ?", (userid,))
    results = c.fetchall()

    decrypted_data = []
    for row in results:
        id, website, username, password = row
        decrypted_password = decrypt_password(password, key)
        decrypted_data.append([id, website, username, decrypted_password])

    headers = ["ID", "Website", "Username", "Password"]

    if decrypted_data == []:
        input("No Passwords Saved! Add one First")
        input()
        main_menu(userid, mstpassword)
    else:
        print(tabulate(decrypted_data, headers=headers, tablefmt="grid"))
        delete_choice = input("""Enter ID of password you would like to delete, enter "Exit" to go back: """).lower()
        if delete_choice == "exit":
            print("Goodbye!")
            time.sleep(1)
            main_menu(userid, mstpassword)
        else:
            confirmation = input(f"Are you sure you want to delete {delete_choice}? (Type y/n)> ")
            if confirmation == "y":
                c.execute(f"DELETE FROM passwords WHERE id = ?", (delete_choice,))
            else:
                print("Goodbye!")
                time.sleep(1)
                main_menu(userid, mstpassword)

def update_password(userid, key, mstpassword):
    c.execute("SELECT id, website, username, password FROM passwords WHERE userid = ?", (userid,))
    results = c.fetchall()

    decrypted_data = []
    for row in results:
        id, website, username, password = row
        decrypted_password = decrypt_password(password, key)
        decrypted_data.append([id, website, username, decrypted_password])

    headers = ["ID", "Website", "Username", "Password"]

    if decrypted_data == []:
        input("No Passwords Saved! Add one First")
        input()
        main_menu(userid, mstpassword)
    else:
        print(tabulate(decrypted_data, headers=headers, tablefmt="grid"))
        id_choice = input("""Enter ID of password you would like to update, enter "Exit" to go back: """).lower()
        if id_choice == "exit":
            print("Goodbye!")
            time.sleep(1)
            main_menu(userid, mstpassword)
        else:
            new_choice = input("What would you like to update this password too? > ")
            confirmation = input(f"Are you sure you want to update {id_choice}'s password to {new_choice}? (Type y/n)> ")
            if confirmation == "y":
                c.execute(f"UPDATE passwords SET password = ? WHERE id = ?", (new_choice, id_choice))
                input("Success! Press enter to continue...")
                main_menu(userid, mstpassword)
            else:
                print("Goodbye!")
                time.sleep(1)
                main_menu(userid, mstpassword)

def main_menu(userid, password):
    try:
        c.execute("SELECT salt FROM users WHERE id = ?", (userid,))
        result = c.fetchone()

        if result:
            salt = result[0]
            derived_key = derive_key(password, salt)
        else:
            print("Error: Could not retrieve salt for the user.")
            return

    except Exception as e:
        print("Error Code is: ", e)
        return
    
    clear_screen()
    option = input(f"Please select an option\n1. View Saved Passwords\n2. Add Password\n3. Delete Saved Password\n4. Update Saved Password\n5. Sign Out\n\n> ")
    if option == "1":
        view_passwords(userid, derived_key, password)
    elif option == "2":
        add_password(userid, derived_key, password)
    elif option == "3":
        delete_password(userid, derived_key, password)
    elif option == "4":
        update_password(userid, derived_key, password)
    elif option == "5":
        login_menu()
        return
    else:
        input("Invalid input")
        clear_screen()
        main_menu(userid, password)

def signin():
    # Signin Menu
    clear_screen()
    print("Welcome Back! (Enter 1 to return to the main menu): ")
    username = input("Please enter your username: ")

    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    useresult = c.fetchone()

    if username == useresult:
        password = input("Please enter your password: ")
        hashed_pass_key = hash_password(password)

        # This will be placed in a try command to stop errors from crashing program
        try:
            c.execute("SELECT id, mstpassword FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if result and hashed_pass_key == result[1]:
                print("Welcome Back! Press enter to continue...")
                input()
                main_menu(result[0], password)
            else:
                print("Incorrect password or username, please try again...")
                input()
                signin()
        except Exception as e:
            print(f"Error Code is: ", e)
            input()
            signin()

        if result and hashed_pass_key == result[1]:
            print("Welcome Back! Press enter to continue...")
            input()
            main_menu(result[0], password)
        else:
            print("Incorrect password or username, please try again...")
            input()
            signin()
    elif username == "1":
        login_menu()




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
        salt = os.urandom(16)
        hashed_mst_passkey = hash_password(mstpassword)
        c.execute(f"INSERT INTO users (username, mstpassword, salt) VALUES (?, ?, ?)", (username, hashed_mst_passkey, salt))
        conn.commit()
        print("Your Account has been Successfully Created! Press enter to continue...")
        input()
        signin()

login_menu()
