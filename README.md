# Secure Password Manager

## Overview

Welcome to the **Secure Password Manager** project! This Python-based application is designed to store and manage your passwords securely. Utilizing robust encryption and hashing mechanisms, this password manager ensures that your sensitive information is protected. Whether you're a seasoned developer or an employer looking to gauge my skills, this project demonstrates my expertise in Python, cybersecurity, and database management.

## Features

- **User Authentication**: Create and manage multiple accounts with securely hashed master passwords using bcrypt.
- **Password Encryption**: Store passwords securely with encryption using the `cryptography.fernet` module.
- **Password Management**: Easily add, view, update, and delete stored passwords in a user-friendly interface.
- **Data Protection**: Each password is encrypted with a unique key derived from the master password and a randomly generated salt.
- **Cross-Platform Compatibility**: The application runs seamlessly on both Windows and Unix-based systems.

## Technology Stack

- **Python**: Core programming language used to build the application.
- **SQLite**: Database management system to store user credentials and encrypted passwords.
- **bcrypt**: Used for securely hashing user passwords.
- **Fernet Encryption (cryptography.fernet)**: Ensures that all stored passwords are encrypted and secure.
- **Tabulate**: Provides a neat and organized display of stored passwords.

## How It Works

1. **Database Setup**: 
   - The application connects to an SQLite database (`password_manager.db`), creating tables for users and passwords if they don't already exist.
   
2. **User Authentication**: 
   - Users can create a new account or sign in to an existing one. Passwords are hashed using bcrypt for security.
   
3. **Password Management**:
   - Users can add, view, update, or delete passwords. Passwords are encrypted before being stored in the database, ensuring they are never saved in plain text.
   
4. **Encryption/Decryption**:
   - The master password is used to derive an encryption key, which is then used to encrypt and decrypt stored passwords using the Fernet encryption.

## Getting Started

### Prerequisites

- **Python 3.x**: Ensure Python is installed on your system.
- **Required Libraries**: Install dependencies using pip:

    ```bash
    pip install bcrypt cryptography tabulate
    ```

### Running the Application

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/your-username/secure-password-manager.git
    cd secure-password-manager
    ```

2. **Run the Application**:

    ```bash
    python password_manager.py
    ```

3. **Follow the On-Screen Prompts**:
   - Create an account or log in to manage your passwords securely.

## Future Improvements

- **Two-Factor Authentication (2FA)**: Adding an extra layer of security during the login process.
- **Password Strength Checker**: Ensure that users create strong passwords.
- **Backup and Restore**: Allow users to back up their encrypted passwords and restore them when needed.
