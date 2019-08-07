#!/usr/bin/python3
import os
import random as rn
import time
import xml.etree.ElementTree as ET
import hashlib
from AESCipher import AESCipher
from Database import Database

# ============ GLOBAL VARS =====================================================

# ============ UTILITIES =======================================================
def print_header(text):
    text = " " + text + " "
    htl = int(len(text)/2)
    number_of_hashes = 20
    total_len = (number_of_hashes - htl) if number_of_hashes - htl > 0 else 2
    print("\n" + "#"*total_len + text + "#"*total_len)
    print_separator(number_of_hashes)

def print_separator(number_of_hashes):
    print("-"*(number_of_hashes * 2 + 1))

def print_error(text):
    text = " " + text + " "
    htl = int(len(text)/2)
    number_of_dashes = 20
    total_len = (number_of_dashes - htl) if number_of_dashes - htl > 0 else 2
    print("\n<!>" + "<!>"*total_len + text + "<!>"*total_len + "<!>")

def hash_string(string):
    """
    Return a SHA-256 hash of the given string
    """
    return hashlib.sha256(string.encode('utf-8')).hexdigest()

def generatePassword(len=8):
    pattern=""
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    specials = "@/$&"
    # Generate a random pattern
    for i in range(0, len):
        pattern += rn.choice([lowercase[0], uppercase[0], digits[0], specials[0]])
        result = ""
    # Fill the random pattern with random characters taken from the appropriate
    # category
    for i in pattern:
        if(i == "a"):
            result = result + rn.choice(lowercase)
        elif(i == "A"):
            result = result + rn.choice(uppercase)
        elif(i == "@"):
            result = result + rn.choice(specials)
        else:
            result = result + rn.choice(digits)
    return result

# ============= MISC FUNCTIONS =============================================
def menu():
    key = input_and_test_password()
    if(key is None):
        print_error("Go fuck yourself ( ͡° ͜ʖ ͡°)")
        return 0

    choice = -1
    root = None
    entries = load(key)

    while(choice != 0):
        print_header("Main Menu")
        print("1) Print everything")
        print("2) Add new entry")
        print("3) Edit entries")
        print("4) Delete entries")
        print("")
        print("5) Change master password") # TODO
        print("6) Save current entries state")
        print("0) Quit")
        try:
            choice = int(input(">> Choice: "))
        except KeyboardInterrupt:
            print_error("Bye Bye")
            break
        except ValueError:
            os.system("clear")
            print_error("I need an integer")
        if(choice == 1):
            print_all_entries(entries)
        elif(choice == 2):
            result = new_entry()
            if(result != None):
                entries.append(result)
        elif(choice == 3):
            entries = edit_entry(entries)
        elif(choice == 4):
            entries = delete_entries(entries)
        elif(choice == 5):
            os.system("clear")
            change_master_password()
        elif(choice == 6):
            os.system("clear")
            save(key, entries)
            print_error("Saved successfully")
    print_error("Bye Bye")
    return 0

# ============= PASSWORDS FUNCTIONS =================================================

def print_all_entries(entries):
    counter = 1
    str = ""
    max_len = 0
    os.system("clear")
    print_header("Your passwords")
    for entry in entries:
        str = "{}) {} | {} | {}".format(counter, entry[0], entry[1], entry[2])
        counter += 1
        # We calculate how long the separator has to be for it to look nice
        if(max_len < len(str)):
            max_len = len(str)
        print(str)
    print("-" * max_len + "\n")

def change_master_password():
    db = Database()
    new_master_password = "a"
    confirm_new_master_password = "b"
    try:
        while(new_master_password != confirm_new_master_password):
            print_header("Changing Master Password")
            new_master_password = input("Input the new master password:")
            confirm_new_master_password = input("Confirm the new master password:")
            if(new_master_password != confirm_new_master_password):
                print_error("The passwords do not correspond. Retry")
                continue
    except KeyboardInterrupt as e:
        os.system("clear")
        print_error("Aborted")
        return 1
    db.update_masterpassword(new_master_password)

def new_entry():
    print_header("New entry")
    service = input("> Service: ")
    username = input("> Username: ")
    password = input("> password: ")
    # Calculate how many inputs were empty
    empties = 0
    if(service == ""):
        empties += 1
    if(username == ""):
        empties += 1
    if(password == ""):
        empties += 1
    if(empties < 3):
        return [service, username, password]
    else:
        print_error("Not enough data to insert in the database (minimum 1)")
    return None

def edit_entry(entries):
    print_header("Edit entries")
    print_all_entries(entries)
    print_separator(20)
    tmp_entry = []
    retry = True
    try:
        while(retry):
            retry = False
            print_all_entries(entries)
            try:
                choice = int(input("-->Choice: "))
            except ValueError:
                os.system("clear")
                print_error("I need an integer!")
                retry = True
                continue
            # Check if the chosen index is in the entries range
            if(choice < 0 or choice > len(entries)):
                os.system("clear")
                print_error("Out of bounds! choice must be 0 <= choice <= {}".
                    format(len(entries)))
                retry = True
        print("Editing: {}) [{}, {}, {}]".format(choice, entries[choice - 1][0],
                                                        entries[choice - 1][1],
                                                        entries[choice - 1][2],))

        # Rollback in case something bad happens
        tmp_entry = entries[choice - 1]

        # Get the new values for the attributes, "" means Do not edit
        service = input("> Service: ")
        username = input("> Username: ")
        password = input("> password: ")
        entries[choice - 1][0] = entries[choice - 1][0] if service == "" else service
        entries[choice - 1][1] = entries[choice - 1][1] if username == "" else username
        entries[choice - 1][2] = entries[choice - 1][2] if password == "" else password
    except KeyboardInterrupt:
        os.system("clear")
        print_error("Aborted")
        # Rollback
        entries[choice - 1] = tmp_entry
    return entries

def delete_entries(entries):
    os.system("clear")
    print_header("Delete entries")
    print_all_entries(entries)
    # The entries we want to delete can be indicated on a single line,
    # separated by a space
    choices = input("-->Input the indexes: ").split()
    for choice in choices:
        try:
            entries[int(choice) - 1] = []
        #Ignore bad inputs
        except IndexError as e:
            pass
        except ValueError as e:
            pass
    os.system("clear")
    # create a new entries list consisting of only non-empty entries
    return [entry for entry in entries if entry]

# ============= SECURITY FUNCTIONS ==============================================
def save(key, entries):
    """ Encrypt the passwords we stored in RAM and write them to the database """
    db = Database()
    cipher = AESCipher(key)
    tmp = []
    for entry in entries:
        entry_2 = cipher.encrypt(entry[2])
        tmp.append([entry[0], entry[1], entry_2.decode()])
    # Write the encrypted passwords to the database
    if(db.update(tmp)):
        print_error("Couldn't save")

def load(key):
    """ Get the passwords stored in the database and decrypt them """
    cipher = AESCipher(key)
    db = Database()
    entries = db.load_entries()
    tmp = []
    for entry in entries:
        try:
            entry_2 = cipher.decrypt(entry[2])
        except Error as e:
            print("Error: " + str(e))
        tmp.append([entry[0], entry[1], entry_2])
    return tmp

def input_and_test_password():
    """ 'Login' function. It tests if the user trying to access the passwords
        is the legitimate owner of such passwords.
        Returns: the input password if it's succesfully authenticated or None otherwise
    """
    os.system("clear")
    db = Database()
    print_header("Makin\' Bacon")
    # Make the user input the password, hash it and compare the hash to the one
    # stored in the database
    attacking = input("> Insert password: ") # user input
    defending = db.get_masterpassword()[0] # database retrieval
    if(hash_string(attacking) == defending):
        # We return the input password because it will serve as the encryption key
        return attacking
    else:
        # The user failed to authenticate
        return None



def main():
    menu()

if __name__ == '__main__':
    main()
