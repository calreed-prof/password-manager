import os
import sqlite3
import hashlib
import getpass

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

def main_menu(userid):
    option = input(f"Please select an option\n1. View Saved Passwords\n2. Add Password\n3. Delete Saved Password\n4. Update Saved Password")

def signin():
    # Signin Menu
    clear_screen()
    backout = input("Welcome Back!\n(Press 1 to return to the main menu): ")
    if backout == 1:
        login_menu()
    else:
        pass
    username = input("Please enter your username: ")
    password = getpass.getpass("Please enter your password: ")
    hashed_pass_key = hashlib.sha256(password.encode()).hexdigest()

    # This will be placed in a try command to stop errors from crashing program
    try:
        c.execute(f"SELECT id, password FROM users Where username = ?", (username))
        result = c.fetchone()
        if result and hashed_pass_key == result[1]:
            print("Welcome Back! Press enter to continue...")
            input()
            main_menu(result[0])
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
        hashed_mst_passkey = hashlib.sha256(mstpassword.encode()).hexdigest()
        c.execute(f"INSERT INTO users (username, mstpassword) VALUES (?, ?, ?)", (username, hashed_mst_passkey))
        conn.commit()
        print("Your Account has been Successfully Created! Press enter to continue...")
        input()
        signin()
        

login_menu()
