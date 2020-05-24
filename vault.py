import json
import base64
from Crypto.Cipher import AES
import pyfiglet
import os
from getpass import getpass
import sys
import bcrypt

# Function to Load User details from the locally saved file
def loadUser(username):
    details = {}
    savedir = os.getcwd() + "\\data\\"
    filename = username + '.json'
    try:
        file = open(savedir + filename, 'rb+')
        details = json.load(file)
    except:
        if(not os.path.isdir(savedir)):
            os.mkdir(savedir)
        file = open(savedir + filename, 'wb+')
    file.close()
    return details

# Encrypt the username and password using the master credentials
def encryptService(service, username, password, masterusername, masterpass):
    if(len(masterpass) != 16 or len(masterusername) != 16):
        print("Master Username and Password must be exactly 16 characters!")
        return
    details = loadUser(masterusername)
    aes_obj = AES.new(masterusername.encode("utf8"), AES.MODE_CFB, masterpass.encode("utf8"))
    encrypt_user = aes_obj.encrypt(username.encode("utf8"))
    encrypt_pass = aes_obj.encrypt(password.encode("utf8"))

    encoded_user = base64.encodebytes(encrypt_user)
    encoded_pass = base64.encodebytes(encrypt_pass)

    account = {
    "username" : encoded_user.decode('ascii'),
    "password" : encoded_pass.decode('ascii')
    }

    save(masterusername, service, account)
    return account

# Decrypt the username and password for an account using master credentials
def decryptService(account, masterusername, masterpass):
    try:
        aes_obj = AES.new(masterusername.encode("utf8"), AES.MODE_CFB, masterpass.encode("utf8"))
        username = bytes(account["username"], encoding='utf8')
        username = aes_obj.decrypt(base64.decodebytes(username))
        password = bytes(account["password"], encoding='utf8')
        password = aes_obj.decrypt(base64.decodebytes(password))
        print("\n")
        print("Username: ", username.decode("utf8"))
        print("Password: ", password.decode("utf8"))
        print("\n")
    except:
        print("Incorrect Password")
        sys.exit()
# Save an encrypted account under the user
def save(username, service, account):
    savedir = os.getcwd() + '\\data\\' + username + '.json'
    details = loadUser(username)
    details[service] = account
    with open(savedir, 'w') as file:
        json.dump(details, file)
    return True

# Retrieve the account credentials of a service under a user
def retrieve(service, masterusername, masterpass):
    details = loadUser(masterusername)
    if(service in details):
        decryptService(details[service], masterusername, masterpass)
        return True
    else:
        print("No account under " + service)
        return False

# Get all the services saved under the user
def all(username):
    accounts = loadUser(username)
    for key, value in accounts.items():
        print(key)

def getConfig():
    config = {}
    exists = False
    filename = "config.json"
    try:
        file = open(filename, 'rb+')
        config = json.load(file)
        exists = True
    except:
        file = open(filename, 'wb+')
    file.close()
    return exists, config

# Authenticates the user
def authenticate(user, password):
    savedPass = ""
    if bcrypt.checkpw(password.encode('utf-8'), savedPass):
        return True
    else:
        return False
    pass

def checkUserExist(username):
    savedir = os.getcwd() + '\\data\\' + username + '.json'
    if(not os.path.isdir(savedir)):
        return False
    else:
        return True

# This function checks the saved file to make sure an account under the given service exists
def checkAccountExist(username, service):
    accounts = loadUser(username)
    if(service in accounts):
        return True
    else:
        return False

if __name__ == "__main__":
    ascii_banner = pyfiglet.figlet_format("Vault")
    welcome_msg = "Welcome to Vault, this service encrypts user accounts and securely stores them.\nTo continue, please enter your username and password\n"
    help_msg = "To Add an account, enter add.\nTo decrypt an account, enter decrypt.\nTo view all accounts, enter all.\nTo exit, enter exit.\n"
    print(ascii_banner)
    print(welcome_msg)
    master_username = ""
    while(len(master_username) != 16):
        master_username = input("Master Username: ")
        if(len(master_username)!=16):
            print("ERROR! Master Username must be exactly 16 characters!")

    master_password = ""
    while(len(master_password) != 16):
        master_password = getpass("Master Password: ")
        if(len(master_password)!=16):
            print("ERROR! Master Password must be exactly 16 characters!")

    # master_password = getpass("Master Password: ")
    print('\n')
    if(checkUserExist):
        print("Accounts under", master_username)
        all(master_username)
    else:
        print("No record found for", master_username, ". A new record will be created.")
        print('\n')

    command = ""

    while(command != "exit"):
        print("\n")
        print(help_msg)
        command = input("Enter command: ")
        print("\n")
        if(command == "add"):
            added = False
            while(not added):
                service = input("Enter the account name: ")
                if(checkAccountExist(master_username, service)):
                    confirmation = input("An account already exists under that name. To overwrite the existing account enter Y, anything else otherwise: ")
                    if(confirmation == "Y"):
                        username = input("Enter username: ")
                        password = input("Enter password: ")
                        encryptService(service, username, password, master_username, master_password)
                        added = True
                else:
                    username = input("Enter username: ")
                    password = input("Enter password: ")
                    encryptService(service, username, password, master_username, master_password)
                    added = True

        if(command == "decrypt"):
            service = input("Enter the account you want to decrypt: ")
            retrieve(service, master_username, master_password)
        if(command == "all"):
            all(master_username)


