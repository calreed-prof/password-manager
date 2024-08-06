import os
import sqlite3
import hashlib

# This is going to be the connection setup for the database
conn = sqlite3.connect("password_manager.db")
c = conn.cursor()

# This just clears the terminal
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

c.execute('''Create TABLE IF NOT EXISTS passwords (
          id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
          website TEXT NOT NULL,
          username TEXT NOT NULL,
          password TEXT NOT NULL
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

def signin():
    # Signin Menu
    clear_screen()
    print("Welcome Back!\n(Press 1 to return to the main menu): ")
    pass_key = input("Enter your password to continue: ")
    hashed_pass_key = hashlib.sha256(pass_key.encode()).hexdigest()
    try:
        c.execute("SELECT password FROM passwords WHERE website = 'Master Password'")
        result = c.fetchone()[0]
        if hashed_pass_key == result:
            print("Welcome Back!")

        elif pass_key == "1":
            login_menu()
        else:
            print("Invalid password, please try again.Press enter to continue...")
            input()
            signin()
    except:
        print("Invalid password, please try again.Press enter to continue...")
        input()
        signin()

def create_account():
    # Create Account Menu
    clear_screen()
    pass_key = input("Enter your Master Password (This should be different than all other passwords): ")
    re_enter_pass_key = input("Please re-enter your Master Password: ")
    if pass_key == re_enter_pass_key:
        hashed_pass_key = hashlib.sha256(pass_key.encode()).hexdigest()
        c.execute(f"INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", ("Master Password", "Master Password", hashed_pass_key))
        conn.commit()
        print(f"Your Master Password has been set!\nPlease press enter to continue...")
        input()
        signin()
    else:
        print("Your Master Password does not match, please try again.\nPress enter to continue")
        input()
        create_account()

login_menu()
