#!/usr/bin/python3
import os
import time
import xml.etree.ElementTree as ET
import hashlib
from AESCipher import AESCipher
import Password
from Database import Database

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
    tuples = []
    while(choice != 0):
        print_header("Main Menu")
        print("1) Print everything")
        print("2) Add new entry")
        print("3) Delete entries")
        print("4) Modify entries")
        print("")
        print("5) Load from file")
        print("6) Change master password") # TODO
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
#            tuples = get_all_tuples(root)
            print_header("Choice is equal to 1")
            encrypt(key)
            decrypt(key)
#            print_all_tuples(tuples)
        elif(choice == 2):
            add_tuple()
        elif(choice == 5):
            root = load_from_file()
        elif(choice == 6):
            change_master_password()
    print_error("Bye Bye")
    return 0
# ============= PASSWORDS FUNCTIONS =================================================
def get_all_tuples(root):
    if(root == None):
        return []
    tuples = []
    tmp = []
    for tuple in root.findall("tuple"):
        for attribute in tuple:
            tmp.append(attribute.text)
        password = Password.Password(tmp[0], tmp[1], tmp[2]).new()
        tuples.append(password)
        tmp = []
    return tuples

def print_all_tuples(tuples):
    counter = 1
    str = ""
    max_len = 0
    os.system("clear")
    print_header("Your passwords")
    for password in tuples:
        str = "{}) {} | {} | {}".format(counter, password.get_service(), password.get_username(), password.get_password())
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

def add_tuple():
    database = Database()
    print_header("New entry")
    service = input("> Service:")
    username = input("> Username:")
    password = input("> password:")
    empties = 0
    if(service == ""):
        empties += 1
    if(username == ""):
        empties += 1
    if(password == ""):
        empties += 1
    if(empties < 2):
        database.insert(service, username, password)
    else:
        print_error("Not enough data to insert in the database (minimum 1)")
    database.quit()

# ============= SECURITY FUNCTIONS ==============================================
def encrypt(key):
    cipher = AESCipher(key)
    db = Database()
    tuples = db.load_entries()
    tmp = []
    print(tuples)
    for tuple in tuples:
        tuple_2 = cipher.encrypt(tuple[2])
        tmp.append([tuple[0], tuple[1], tuple_2])
    db.update_passwords(tmp)

def decrypt(key):
    cipher = AESCipher(key)
    db = Database()
    tuples = db.load_entries()
    tmp = []
    print(tuples)
    for tuple in tuples:
        tuple_2 = cipher.decrypt(tuple[2])
        tmp.append([tuple[0], tuple[1], tuple_2])
    db.update_passwords(tmp)

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

# ============= FILES FUNCTIONS =================================================
def load_from_file():
    os.system("clear")
    default_dir = "passwords/"
    files = get_all_xml_files_from_filenames_array(get_all_files(default_dir))
    counter = list_xml_files(files, default_dir)
    choice = int(input(">> Load from: "))
    while(choice >= counter):
        os.system("clear")
        dir = input(">> Dir: ")
        files = get_all_xml_files_from_filenames_array(get_all_files(dir))
        counter = list_xml_files(files, dir)
        choice = int(input(">> Load from: "))
    os.system("clear")

    return ET.parse(files[choice - 1]).getroot()


def get_all_files(dir):
    files =  []
    for dirpath, dirnames, filenames in os.walk(dir):
        files.extend(filenames)
    return files
def get_all_xml_files_from_filenames_array(filenames):
    return [filename for filename in filenames if ".xml" in filename]

def list_xml_files(files, dir):
    os.system("clear")
    print("Listing {}. Load from:".format(dir))
    counter = 1
    for file in files:
        if(".xml" in file):
            print("{}) {}".format(counter, file))
            counter += 1
    print("\n{}) Load from another directory".format(counter))
    return counter

def list_to_xml(list):
    pass


def main():
    menu()

if __name__ == '__main__':
    main()
