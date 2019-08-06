#!/usr/bin/python3
import os
import time
import xml.etree.ElementTree as ET
import hashlib
from AESCipher import AESCipher
import Password
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
        print("3) Delete entries")
        print("4) Modify entries")
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
        elif(choice == 5):
            change_master_password()
        elif(choice == 6):
            save(key, entries)
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
        if(max_len < len(str)):
            max_len = len(str)
        print(str)
    print("-" * max_len + "\n")

def change_master_password():
    db = Database()
    new_master_password = "a"
    confirm_new_master_password = "b"
    while(new_master_password != confirm_new_master_password):
        print_header("Changing Master Password")
        new_master_password = input("Input the new master password:")
        confirm_new_master_password = input("Confirm the new master password:")
        if(new_master_password != confirm_new_master_password):
            print_error("The passwords do not correspond. Retry")
            continue

    db.update_masterpassword(new_master_password)

def new_entry():
    print_header("New entry")
    service = input("> Service: ")
    username = input("> Username: ")
    password = input("> password: ")
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

# ============= SECURITY FUNCTIONS ==============================================
def save(key, entries):
    db = Database()
    cipher = AESCipher(key)
    tmp = []
    for entry in entries:
        entry_2 = cipher.encrypt(entry[2])
        tmp.append([entry[0], entry[1], entry_2.decode()])
    if(db.update(tmp)):
        print_error("Couldn't save")

def load(key):
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
    os.system("clear")
    db = Database()
    print_header("Makin\' Bacon")
    attacking = input("> Insert password: ")
    defending = db.get_masterpassword()[0]
    if(hash_string(attacking) == defending):
        return attacking
    else:
        return None



def main():
    menu()

if __name__ == '__main__':
    main()
