#google drive API download then upload

import os
import platform
import secrets
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import getpass

fernet = None

def create_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def ask_master_password():
    salt = b''
    salt_file = 'salt.bin'
    if not os.path.exists(salt_file):
        print("First time setup.")
        while True:
            password = input("Create Master Password: ")
            confirm = input("Confirm Master Password: ")
            if password != confirm:
                print("Passwords do not match. Try again.")
            else:
                break

        salt = os.urandom(16)
        with open(salt_file, 'wb') as f:
            f.write(salt)
        print("Master password set successfully.")
    else:
        password = getpass.getpass("Enter Master Password: ")
        with open(salt_file, 'rb') as f:
            salt = f.read()

    key = create_key(password, salt)
    return Fernet(key)

def sql_database():
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS info (
            app TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def storage(app, username, password):
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    encrypted_password = fernet.encrypt(password.encode()).decode()

    try:
        cursor.execute(
            'INSERT INTO info (app, username, password) VALUES (?, ?, ?)',
            (app.lower(), username, encrypted_password)
        )
        conn.commit()
        print(f"Stored login for '{app}'.")

    except sqlite3.IntegrityError:
        print(f"An entry for '{app}' already exists.")

    finally:
        conn.close()

def check_if_exists(app):
    app = app.strip().lower()
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password FROM info WHERE app = ?', (app,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return True, result
    else:
        return False, None

def generate_password(length=15):
    letters_cap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    letters_lower = 'abcdefghijklmnopqrstuvwxyz'
    numbers = '0123456789'
    special_characters = '!@#$%^&*()_+-=?'
    all_characters = letters_cap + letters_lower + numbers + special_characters

    password = [secrets.choice(letters_cap),
                secrets.choice(letters_lower),
                secrets.choice(numbers),
                secrets.choice(special_characters)
    ]

    for i in range(length-4):
        password.append(secrets.choice(all_characters))

    secrets.SystemRandom().shuffle(password)
    final_password = ''.join(password)
    print(final_password)
    return final_password

def recall_login():
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    cursor.execute('SELECT app FROM info')
    rows = cursor.fetchall()

    print('Stored apps: ')
    for row in rows:
        print(row[0])

    get = input('Enter the app name to recall login: ').strip().lower()

    cursor.execute('SELECT username, password FROM info WHERE app = ?', (get,))
    login = cursor.fetchone()
    conn.close()

    if login:
        try:
            decrypted_password = fernet.decrypt(login[1].encode()).decode()
            print(f'Login for {get}\n Username: {login[0]}\n Password: {decrypted_password}')
        except Exception as e:
            print('Failed to decrypt password:', e)
        return True, login
    else:
        print('Invalid app name or does not exist, please try again.')
        return False, None

def delete_account():
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    cursor.execute('SELECT app FROM info')
    rows = cursor.fetchall()
    print('Stored apps: ')
    for row in rows:
        print(row[0])

    remove = input('Enter the app name to delete account: ').strip().lower()
    app_names = []
    for row in rows:
        app_names.append(row[0].lower())
    if remove not in app_names:
        print('Invalid app name or does not exist, please try again.')
        return False, None
    else:
        check = input('Are you sure you want to delete the account?\nThis cannot be undone\n(y/n): ').strip().lower()
        if check == 'y':
            cursor.execute('DELETE FROM info WHERE app = ?', (remove,))
            print('Account was successfully deleted.')
            conn.commit()
        if check == 'n':
            print('Canceled.')
            conn.close()
        return True

def check_os():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

def clean_and_exit():
    check_os()
    print('Exiting Securely')

def return_to_beginning():
    check_os()
    main()


def main():
    global fernet
    check_os()
    fernet = ask_master_password()
    sql_database()

    while True:
        action = input('Would you like to generate a password or recall a login or Delete an account?\n(Generate or Recall or Delete): ').strip().lower()
        if action == 'generate':
            app = input('Enter the app name: ').strip().lower()
            exists, result = check_if_exists(app)
            if exists:
                print(f"An entry for '{app}' already exists.")
                choice = input('Would you like to receive login (y/n)? ').strip().lower()
                if choice == 'y':
                    username, encrypted_password = result
                    try:
                        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                        print(f"\nLogin for '{app}':\nusername:{username}\npassword:{decrypted_password}\n")
                    except Exception as e:
                        print('Failed to decrypt password:', e)
                else:
                    print('No login will be shown')
            else:
                username = input('Enter the username: ')
                password = generate_password(length=15)
                storage(app, username, password)
        elif action == 'recall':
            recall_login()
        elif action == 'delete':
            delete_account()
        else:
            print('Action Unknown, Please Selected One of the Options')

    while True:
        outro = input('Return to Beginning or Exit?(Return or Exit): ').lower()
        if outro == 'exit':
            clean_and_exit()
            break
        if outro == 'return':
            return_to_beginning()
            break
        else:
            print('Action Unknown, Please Selected One of the Options')

# start program
if __name__ == '__main__':
    main()