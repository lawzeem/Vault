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
        return False
    if(len(username) == 0):
        print("Error! Username cannot be blank.")
        return False
    if(len(password) == 0):
        print("Error! Password cannot be blank.")
        return False
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
    return True

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
        print("Error Decrypting! Incorrect Username or Password given.")
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

# Returns the number of accounts under the user
def count(usesrname):
    accounts = loadUser(username)
    return len(accounts)

# This function gets the config
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

# This function creates a config file
def createConfig():
    config = {}
    filename = "config.json"
    vault_user = vault_pass1 = vault_pass2 = ""
    while(len(vault_user)!=16):
        vault_user = input("Vault Username:")
        if(len(vault_user)!=16):
            print("Username must be exactly 16 characters!")
    while(len(vault_pass1)!=16):
        vault_pass1 = getpass("Vault Password:")
        if(len(vault_pass1)!=16):
            print("Password must be exactly 16 characters!")
    while(vault_pass2!=vault_pass1):
        vault_pass2 = getpass("Vault Password (again):")
        if(vault_pass2!=vault_pass1):
            print("Passwords must match!")
    config["username"] = vault_user
    bytePass = vault_pass1.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytePass, salt)
    hashed = hashed.decode('ascii')
    config["password"] = hashed
    with open(filename, 'w+') as file:
        json.dump(config, file)
    return vault_user, vault_pass1

# Authenticates the user
def authenticate(userconfig, password):
    savedPass = userconfig["password"].encode('utf8')
    password = password
    while(not bcrypt.checkpw(password.encode('utf-8'), savedPass)):
        password = getUserDet()
    return True

# Checks if the user exists
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

# This function gets the vault username and password from the terminal and returns them
def getUserDet():
    master_password = ""
    while(len(master_password) != 16):
        master_password = getpass("Vault Password: ")
        if(len(master_password)!=16):
            print("ERROR! Vault Password must be exactly 16 characters!")

    return master_password

# Delete a service
def delete(service, user):
    details = loadUser(user)
    if(service in details):
        details.pop(service)
        savedir = os.getcwd() + '\\data\\' + user + '.json'
        with open(savedir, 'w') as file:
            json.dump(details, file)
    else:
        print("Error! No such service by that name.")

# This is the main function that asks for inputs and gives output
def runCommand(username, password):
    command = ""
    while(command != "exit"):
        command = input("vault> ")
        commands = command.split()
        if(len(commands) == 2):
            command = commands[0]
        elif(len(commands) > 2):
            print("Error! Too many arguments")
            break
        command = commands[0].lower()
        # Create
        if(command == "add"):
            added = False
            while(not added):
                if(len(commands) > 1):
                    service = commands[1]
                else:
                    service = input("Enter the account name: ")
                if(checkAccountExist(username, service)):
                    confirmation = input("An account already exists under that name. To overwrite the existing account enter Y: ")
                    if(confirmation.lower() == "y"):
                        acc_username = input("Username: ")
                        acc_password = input("Password: ")
                        added = encryptService(service, acc_username, acc_password, username, password)
                        # added = True
                    else:
                        break
                else:
                    acc_username = input("Username: ")
                    acc_password = input("Password: ")
                    added = encryptService(service, acc_username, acc_password, username, password)
                    # added = True
        # Read
        elif(command == "decrypt"):
            if(len(commands) > 1):
                service = commands[1]
            else:
                service = input("Enter the account you want to decrypt: ")
            retrieve(service, username, password)
        # Update
        elif(command == "edit"):
            updated = False
            while(not updated):
                if(len(commands) > 1):
                    service = commands[1]
                else:
                    service = input("Enter the account name: ")
                if(not checkAccountExist(username, service)):
                    confirmation = input("No account under that name exists! To create a new account enter Y: ")
                    if(confirmation.lower() == "y"):
                        acc_username = input("Username: ")
                        acc_password = input("Password: ")
                        updated = encryptService(service, acc_username, acc_password, username, password)
                        # updated = True
                    else:
                        break
                else:
                    acc_username = input("Username: ")
                    acc_password = input("Password: ")
                    updated = encryptService(service, acc_username, acc_password, username, password)
                    # updated = True
        # Delete
        elif(command == "delete"):
            if(len(commands) > 1):
                service = commands[1]
            else:
                service = input("Enter the account you want to delete: ")
            delete(service, username)
        elif(command == "all"):
            all(username)
        elif(command == "help"):
            print(help_msg)
        elif(command == "exit"):
            break
        else:
            print("Command not recognized, use help for all available commands.")

# Main driver
if __name__ == "__main__":
    # Opener
    ascii_banner = pyfiglet.figlet_format("Vault")
    welcome_msg = "Welcome to Vault, this service encrypts user accounts and securely stores them.\nTo continue, please enter your username and password\n"
    help_msg = "add\t\t\tAdd an account\nadd <account>\t\tAdd the account in the argument\ndecrypt\t\t\tDecrypt an account\ndecrypt <account>\tDecrypt the account in the argument\nedit\t\t\tUpdate an account\nedit <account>\t\tUpdate the account in the argument\ndelete\t\t\tDelete an account\ndelete <account>\tDelete the account in the argument\nall\t\t\tView all accounts\nexit\t\t\tExit vault"
    print(ascii_banner)
    # Checking if a config exists the directory and gets it
    config_exist, config_file = getConfig()

    if(config_exist):
        print("Configuration found, enter password to continue")
        vault_pass = getUserDet()
        vault_user = config_file["username"]
        authenticate(config_file, vault_pass)
        runCommand(vault_user, vault_pass)
    else:
        # Since config does not exist, we make one and then run commands
        print("No configuration found, create one to continue")
        vault_user, vault_pass = createConfig()
        runCommand(vault_user, vault_pass)
