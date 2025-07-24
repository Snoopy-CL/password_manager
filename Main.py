import os
import sys
import platform
import secrets
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import getpass
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.http import MediaFileUpload

# Creates an option to back up info.db to google drive
def cloud_backup():
    CLIENT_SECRET_FILE = 'client-secret.json'
    TOKEN_FILE = 'token.json'
    API_NAME = 'drive'
    API_VERSION = 'v3'
    SCOPES = ['https://www.googleapis.com/auth/drive']

    creds = None

    # Check if token exists which contains users credentials and refresh tokens.
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # refresh tokens if needed. if no valid token, then start up OAuth2 and open local server for login
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    # Build service object for google api with credentials
    service = build(API_NAME, API_VERSION, credentials=creds)
    # Enter the url code after the "/" when entered into the folder you wish to upload to in google drive
    folder_id = ''

    # locate the info.db file
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

    # files to upload to google drive, can put more if needed
    file_names = ['info.db']
    mime_types = ['application/octet-stream']

    # joins file name and mime type, sets name and uploads to google drive
    for file_name, mime_type in zip(file_names, mime_types):
        file_path = os.path.join(base_dir, file_name)
        if not os.path.exists(file_path):
            print(f'File not found: {file_path}')
            continue

        file_metadata = {
            'name': file_name,
            'parents': [folder_id]
        }

        media = MediaFileUpload(file_path, mimetype=mime_type)

        service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()

fernet = None

# Creates key derivation function
def create_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# asks for master password. if its first time running program, asks to set password and creates salt file
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
        # If you want to run on code editor, need to change getpass.getpass to input.
        password = getpass.getpass("Enter Master Password: ")
        with open(salt_file, 'rb') as f:
            salt = f.read()

    key = create_key(password, salt)
    return Fernet(key)

# Creates basic structure of sqlite database file called info.db
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

# Uses info.db to store logins with encryption and specify what components to include in the file
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

# Checks if login currently exists for an app
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

# Checks if the info.db file is empty
def check_if_empty():
    conn = sqlite3.connect('info.db')
    cursor = conn.cursor()

    cursor.execute('SELECT EXISTS(SELECT 1 FROM info LIMIT 1)')
    exists = cursor.fetchone()[0]
    conn.close()
    return exists == 0

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
    return final_password

# Returns the app name of all the saved logins. Allows user to select or check if wanted login is present.
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

# Deletes a saved login previously made
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

# Clears the output depending on the os for security
def check_os():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

# Exits program and clears output
def clean_and_exit():
    check_os()
    print('Exiting Securely')

# Returns to the beginning of program incase user needs to do further actions
def return_to_beginning():
    check_os()
    main()

#Main body of program
def main():
    # Access database and asks user for master password to begin using program
    global fernet
    check_os()
    fernet = ask_master_password()
    sql_database()

    # Gives options to generate a password, recall all the app names of all logins saved, and option to delete previously made login
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
                print(f'The generated password is: {password}')
                storage(app, username, password)
                break
        elif action == 'recall':
            if check_if_empty():
                print('No data was found. You must save an account first.')
            else:
                recall_login()
            break
        elif action == 'delete':
            if check_if_empty():
                print('No data was found. You must save an account first.')
            else:
                delete_account()
            break
        else:
            print('Action Unknown, Please Selected One of the Options')

    # Gives option to return to the beginning of program to do more actions or exit the program.
    # If decided to exit, gives option to backup database of passwords to google drive if wanted.
    while True:
        outro = input('Return to Beginning or Exit?(Return or Exit): ').lower()
        if outro == 'exit':
            update = input('Would you like to update the cloud before you exit? (y/n): ').strip().lower()
            if update == 'y':
                cloud_backup()
                print('File has been backed up to google drive.')
                clean_and_exit()
                break
            else:
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